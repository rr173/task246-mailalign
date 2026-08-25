package service

import (
	"context"
	"path/filepath"
	"testing"

	"task246-mailalign/internal/model"
	"task246-mailalign/internal/store"
)

func TestBug07SealedSampleRejectsTrustMutation(t *testing.T) {
	repository, err := store.Open(filepath.Join(t.TempDir(), "sealed-hop.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	svc := New(repository)
	ctx := context.Background()
	if _, err = svc.SaveSPF(ctx, model.SPFRecord{Domain: "mx.example.com", Version: 1, Mechanisms: []string{"-all"}}); err != nil {
		t.Fatal(err)
	}
	sample, _, err := svc.CreateSample(ctx, model.MessageSample{VisibleFrom: "a@corp.example.com", ReturnPath: "b@mx.example.com", RecipientIP: "192.0.2.10", Body: "message"})
	if err != nil {
		t.Fatal(err)
	}
	hop, err := svc.AddHop(ctx, model.Hop{SampleID: sample.ID, Sequence: 1, FromDomain: "edge.example.net", ByDomain: "mx.example.com", ClientIP: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Analyze(ctx, sample.ID, "missing.example.com", "s1"); err != nil {
		t.Fatal(err)
	}
	if err = repository.UpdateSampleStatus(ctx, sample.ID, model.SampleSealed); err != nil {
		t.Fatal(err)
	}
	if err = svc.TrustHop(ctx, hop.ID); err != model.ErrImmutable {
		t.Fatalf("trusting hop on sealed sample error = %v, want %v", err, model.ErrImmutable)
	}
	stored, err := repository.Hop(ctx, hop.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != model.HopObserved {
		t.Fatalf("sealed hop status changed to %q", stored.Status)
	}
}
