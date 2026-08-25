package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"task246-mailalign/internal/analysis"
	"task246-mailalign/internal/model"
)

func (s *Service) Samples(ctx context.Context) ([]model.MessageSample, error) {
	return s.store.Samples(ctx)
}

func (s *Service) Report(ctx context.Context, sampleID int64) (*model.DiagnosticReport, error) {
	sample, err := s.store.Sample(ctx, sampleID)
	if err != nil {
		return nil, err
	}
	diagnostic, err := s.DiagnosticForSample(ctx, sampleID)
	if err != nil {
		return nil, err
	}
	hops, err := s.store.Hops(ctx, sampleID)
	if err != nil {
		return nil, err
	}
	trusted := 0
	for _, hop := range hops {
		if hop.Status == model.HopTrusted {
			trusted++
		}
	}
	items := analysis.Evidence(analysis.Input{Sample: *sample, Hops: hops}, diagnostic)
	score := analysis.EvidenceScore(items)
	card := analysis.BuildScoreCard(*sample, diagnostic, items)
	report := &model.DiagnosticReport{SampleID: sampleID, MessageKey: sample.MessageKey, SampleStatus: sample.Status, Diagnostic: diagnostic, HopCount: len(hops), TrustedHopCount: trusted, SPFTraceLength: len(diagnostic.SPF.Trace), Evidence: analysis.NormalizeEvidence(analysis.SortEvidence(items)), EvidenceScore: score, Summary: analysis.EvidenceSummary(diagnostic, score), RiskLevel: card.RiskLevel, NextActions: card.NextActions, AuthMethods: card.AuthMethods, DomainRelation: card.DomainRelation}
	if snapshot, snapshotErr := s.store.SnapshotForSample(ctx, sampleID); snapshotErr == nil {
		report.SnapshotID = snapshot.ID
	}
	return report, nil
}

func (s *Service) VerifySnapshot(ctx context.Context, id int64) (map[string]any, error) {
	snapshot, err := s.store.Snapshot(ctx, id)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(snapshot.PayloadJSON))
	computed := hex.EncodeToString(digest[:])
	return map[string]any{"snapshot_id": id, "valid": computed == snapshot.ContentSHA, "stored_sha": snapshot.ContentSHA, "computed_sha": computed, "status": snapshot.Status}, nil
}
