package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"task246-mailalign/internal/model"
)

func (s *Service) PublishSnapshot(ctx context.Context, sampleID int64) (*model.Snapshot, error) {
	diagnostic, err := s.DiagnosticForSample(ctx, sampleID)
	if err != nil {
		return nil, err
	}
	if diagnostic.Status == model.DiagnosticDraft {
		return nil, model.ErrInvalidState
	}
	payload, err := json.Marshal(diagnostic)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	snapshot := &model.Snapshot{SampleID: sampleID, DiagnosticID: diagnostic.ID, Status: model.SnapshotDraft, ContentSHA: hex.EncodeToString(digest[:]), PayloadJSON: string(payload)}
	created, err := s.store.CreateSnapshot(ctx, snapshot)
	if err != nil {
		return nil, err
	}
	published, err := s.store.PublishSnapshot(ctx, created.ID)
	if err != nil {
		return nil, err
	}
	// Sealing the sample freezes the Received hop chain: once an immutable
	// diagnostic snapshot is published, hop trust status cannot be changed.
	if err := s.store.UpdateSampleStatus(ctx, sampleID, model.SampleSealed); err != nil {
		return nil, err
	}
	return published, nil
}

func (s *Service) Snapshot(ctx context.Context, id int64) (*model.Snapshot, error) {
	return s.store.Snapshot(ctx, id)
}
