package service

import (
	"context"
	"path/filepath"
	"testing"

	"task246-mailalign/internal/model"
	"task246-mailalign/internal/store"
)

func TestBug03HopIngestRejectsSequenceGap(t *testing.T) {
	repository, err := store.Open(filepath.Join(t.TempDir(), "hop-gap.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	svc := New(repository)
	ctx := context.Background()
	sample, _, err := svc.CreateSample(ctx, model.MessageSample{VisibleFrom: "a@corp.example.com", ReturnPath: "b@mx.example.com", RecipientIP: "192.0.2.10", Body: "message"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.AddHop(ctx, model.Hop{SampleID: sample.ID, Sequence: 2, FromDomain: "edge.example.net", ByDomain: "mx.example.com", ClientIP: "192.0.2.10"}); err == nil {
		t.Fatal("sequence 2 was accepted before sequence 1")
	}
	hops, err := svc.Hops(ctx, sample.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(hops) != 0 {
		t.Fatalf("invalid hop was persisted: %+v", hops)
	}
}
