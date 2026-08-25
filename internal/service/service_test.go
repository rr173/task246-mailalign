package service

import (
	"context"
	"path/filepath"
	"testing"

	"task246-mailalign/internal/dkim"
	"task246-mailalign/internal/model"
	"task246-mailalign/internal/store"
)

func TestWorkflowPersistsPublishedSnapshot(t *testing.T) {
	dir := t.TempDir()
	repository, err := store.Open(filepath.Join(dir, "mail.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	svc := New(repository)
	body := "body"
	if _, err = svc.SaveSPF(context.Background(), model.SPFRecord{Domain: "mx.example.com", Version: 1, Mechanisms: []string{"ip4:192.0.2.0/24"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.SaveDKIM(context.Background(), model.DKIMRecord{Domain: "signed.example.com", Selector: "s1", Version: 1, BodySHA: dkim.BodySHA(body)}); err != nil {
		t.Fatal(err)
	}
	sample, _, err := svc.CreateSample(context.Background(), model.MessageSample{VisibleFrom: "a@corp.example.com", ReturnPath: "b@mx.example.com", RecipientIP: "192.0.2.3", Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.AddHop(context.Background(), model.Hop{SampleID: sample.ID, Sequence: 1, FromDomain: "edge.example.net", ByDomain: "mx.example.com", ClientIP: "192.0.2.3"}); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Analyze(context.Background(), sample.ID, "signed.example.com", "s1"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := svc.PublishSnapshot(context.Background(), sample.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Status != model.SnapshotPublished {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
	if err = repository.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(filepath.Join(dir, "mail.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err = New(reopened).Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	restored, err := New(reopened).Snapshot(context.Background(), snapshot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if restored.ContentSHA != snapshot.ContentSHA || restored.Status != model.SnapshotPublished {
		t.Fatalf("recovery mismatch: %+v", restored)
	}
}
