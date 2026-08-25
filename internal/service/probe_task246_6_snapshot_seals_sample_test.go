package service

import (
	"context"
	"path/filepath"
	"testing"

	"task246-mailalign/internal/model"
	"task246-mailalign/internal/store"
)

func TestBug06PublishingSnapshotSealsSample(t *testing.T) {
	repository, err := store.Open(filepath.Join(t.TempDir(), "snapshot-seal.db"))
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
	if _, err = svc.Analyze(ctx, sample.ID, "missing.example.com", "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.PublishSnapshot(ctx, sample.ID); err != nil {
		t.Fatal(err)
	}
	stored, err := svc.Sample(ctx, sample.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != model.SampleSealed {
		t.Fatalf("published sample status = %q, want sealed", stored.Status)
	}
}
