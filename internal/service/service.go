package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"task246-mailalign/internal/analysis"
	diagnosticrules "task246-mailalign/internal/diagnostic"
	"task246-mailalign/internal/dkim"
	"task246-mailalign/internal/domain"
	"task246-mailalign/internal/identity"
	"task246-mailalign/internal/model"
	"task246-mailalign/internal/spf"
	"task246-mailalign/internal/store"
)

type Service struct {
	store *store.Store
	mu    sync.Mutex
	locks map[int64]*sync.Mutex
}

func New(repository *store.Store) *Service {
	return &Service{store: repository, locks: map[int64]*sync.Mutex{}}
}
func (s *Service) Store() *store.Store { return s.store }

func (s *Service) sampleLock(id int64) func() {
	s.mu.Lock()
	lock := s.locks[id]
	if lock == nil {
		lock = &sync.Mutex{}
		s.locks[id] = lock
	}
	s.mu.Unlock()
	lock.Lock()
	return lock.Unlock
}

func (s *Service) CreateSample(ctx context.Context, value model.MessageSample) (*model.MessageSample, bool, error) {
	if _, err := domain.MailboxDomain(value.VisibleFrom); err != nil {
		return nil, false, model.ErrInvalidArgument
	}
	if _, err := domain.MailboxDomain(value.ReturnPath); err != nil {
		return nil, false, model.ErrInvalidArgument
	}
	if !domain.ValidIP(value.RecipientIP) || value.Body == "" {
		return nil, false, model.ErrInvalidArgument
	}
	value.MessageKey = identity.MessageKey(value.VisibleFrom, value.ReturnPath, value.RecipientIP, value.Body)
	value.BodySHA = identity.BodySHA(value.Body)
	value.Status = model.SampleReceived
	return s.store.CreateSample(ctx, &value)
}

func (s *Service) Sample(ctx context.Context, id int64) (*model.MessageSample, error) {
	return s.store.Sample(ctx, id)
}

func (s *Service) AddHop(ctx context.Context, value model.Hop) (*model.Hop, error) {
	if err := s.store.EnsureSample(ctx, value.SampleID); err != nil {
		return nil, err
	}
	if value.Sequence < 1 || !domain.ValidIP(value.ClientIP) {
		return nil, model.ErrInvalidArgument
	}
	var err error
	if value.FromDomain, err = domain.Normalize(value.FromDomain); err != nil {
		return nil, model.ErrInvalidArgument
	}
	if value.ByDomain, err = domain.Normalize(value.ByDomain); err != nil {
		return nil, model.ErrInvalidArgument
	}
	value.Status = model.HopObserved
	return s.store.AddHop(ctx, &value)
}

func (s *Service) Hops(ctx context.Context, sampleID int64) ([]model.Hop, error) {
	return s.store.Hops(ctx, sampleID)
}

func (s *Service) SaveSPF(ctx context.Context, value model.SPFRecord) (*model.SPFRecord, error) {
	var err error
	if value.Domain, err = domain.Normalize(value.Domain); err != nil || value.Version < 1 || spf.ValidateMechanisms(value.Mechanisms) != nil {
		return nil, model.ErrInvalidArgument
	}
	value.Status = model.RecordActive
	return s.store.SaveSPF(ctx, &value)
}

func (s *Service) SaveDKIM(ctx context.Context, value model.DKIMRecord) (*model.DKIMRecord, error) {
	var err error
	if value.Domain, err = domain.Normalize(value.Domain); err != nil || value.Selector == "" || value.BodySHA == "" || value.Version < 1 || dkim.ValidateSelector(value.Selector) != nil {
		return nil, model.ErrInvalidArgument
	}
	value.Status = model.RecordActive
	return s.store.SaveDKIM(ctx, &value)
}

func (s *Service) TrustHop(ctx context.Context, id int64) error {
	hop, err := s.store.Hop(ctx, id)
	if err != nil {
		return err
	}
	sample, err := s.store.Sample(ctx, hop.SampleID)
	if err != nil {
		return err
	}
	// A sample is sealed once its diagnostic snapshot has been published; the
	// Received hop chain is then immutable, so its trust status cannot change.
	if sample.Status == model.SampleSealed {
		return model.ErrImmutable
	}
	return s.store.TrustHop(ctx, id)
}

func (s *Service) Analyze(ctx context.Context, sampleID int64, dkimDomain, selector string) (*model.Diagnostic, error) {
	unlock := s.sampleLock(sampleID)
	defer unlock()
	sample, err := s.store.Sample(ctx, sampleID)
	if err != nil {
		return nil, err
	}
	if sample.Status == model.SampleSealed {
		return nil, model.ErrImmutable
	}
	hops, err := s.store.Hops(ctx, sampleID)
	if err != nil {
		return nil, err
	}
	spfRecords, err := s.store.SPF(ctx, "")
	if err != nil {
		return nil, err
	}
	dkimRecords, err := s.store.DKIM(ctx)
	if err != nil {
		return nil, err
	}
	result, err := analysis.Run(analysis.Input{Sample: *sample, Hops: hops, SPF: spfRecords, DKIM: dkimRecords, DKIMDomain: dkimDomain, Selector: selector})
	if err != nil {
		return nil, err
	}
	result.SampleID = sampleID
	result.NeedsReview = diagnosticrules.RequiresReview(result.Status)
	payload, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	result.PayloadJSON = string(payload)
	result, err = s.store.SaveDiagnostic(ctx, result)
	if err != nil {
		return nil, err
	}
	if err := s.store.UpdateSampleStatus(ctx, sampleID, model.SampleAnalyzed); err != nil {
		return nil, err
	}
	return s.hydrateDiagnostic(result)
}

func (s *Service) Diagnostic(ctx context.Context, id int64) (*model.Diagnostic, error) {
	value, err := s.store.Diagnostic(ctx, id)
	if err != nil {
		return nil, err
	}
	return s.hydrateDiagnostic(value)
}

func (s *Service) DiagnosticForSample(ctx context.Context, sampleID int64) (*model.Diagnostic, error) {
	value, err := s.store.DiagnosticBySample(ctx, sampleID)
	if err != nil {
		return nil, err
	}
	return s.hydrateDiagnostic(value)
}

func (s *Service) hydrateDiagnostic(value *model.Diagnostic) (*model.Diagnostic, error) {
	var decoded model.Diagnostic
	if err := json.Unmarshal([]byte(value.PayloadJSON), &decoded); err != nil {
		return nil, fmt.Errorf("decode diagnostic: %w", err)
	}
	decoded.ID, decoded.SampleID, decoded.CreatedAt = value.ID, value.SampleID, value.CreatedAt
	decoded.PayloadJSON = value.PayloadJSON
	return &decoded, nil
}
