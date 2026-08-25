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

func newService(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	repository, err := store.Open(filepath.Join(dir, "mail.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	return New(repository), repository
}

// TestAddHopRejectsSequenceGap ensures that when recording Received hops one
// at a time, a sequence number that would create a gap in the chain is refused
// rather than persisted as a discontinuous link.
func TestAddHopRejectsSequenceGap(t *testing.T) {
	svc, _ := newService(t)
	ctx := context.Background()
	sample, _, err := svc.CreateSample(ctx, model.MessageSample{
		VisibleFrom: "a@corp.example.com", ReturnPath: "b@mx.example.com",
		RecipientIP: "192.0.2.3", Body: "body",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AddHop(ctx, model.Hop{
		SampleID: sample.ID, Sequence: 1, FromDomain: "edge.example.net",
		ByDomain: "mx.example.com", ClientIP: "192.0.2.3",
	}); err != nil {
		t.Fatalf("first hop: %v", err)
	}
	// Sequence 3 while only hop 1 exists -> gap at position 2: must be refused.
	if _, err := svc.AddHop(ctx, model.Hop{
		SampleID: sample.ID, Sequence: 3, FromDomain: "mx.example.com",
		ByDomain: "relay.example.com", ClientIP: "192.0.2.3",
	}); err != model.ErrInvalidArgument {
		t.Fatalf("gap hop: got %v, want ErrInvalidArgument", err)
	}
	// The rejected hop must not have been persisted; the next valid hop is 2.
	hops, err := svc.Hops(ctx, sample.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(hops) != 1 {
		t.Fatalf("expected only one persisted hop, got %d", len(hops))
	}
	if _, err := svc.AddHop(ctx, model.Hop{
		SampleID: sample.ID, Sequence: 2, FromDomain: "mx.example.com",
		ByDomain: "relay.example.com", ClientIP: "192.0.2.3",
	}); err != nil {
		t.Fatalf("second hop: %v", err)
	}
}
