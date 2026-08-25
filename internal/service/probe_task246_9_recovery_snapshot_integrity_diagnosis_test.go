package service

import (
	"context"
	"path/filepath"
	"testing"

	"task246-mailalign/internal/model"
	"task246-mailalign/internal/store"
)

func TestBug09RecoveryDetectsCorruptedPublishedSnapshot(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recovery.db")
	repository, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
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
	snapshot, err := svc.PublishSnapshot(ctx, sample.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repository.DB().ExecContext(ctx, `UPDATE snapshots SET payload_json=payload_json || ? WHERE id=?`, "corruption", snapshot.ID); err != nil {
		t.Fatal(err)
	}
	if err = repository.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err = New(reopened).Recover(ctx); err == nil {
		t.Fatal("recovery accepted a published snapshot whose payload hash no longer matches")
	}
}
