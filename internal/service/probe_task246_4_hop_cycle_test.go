package service

import (
	"context"
	"path/filepath"
	"testing"

	"task246-mailalign/internal/model"
	"task246-mailalign/internal/store"
)

func TestBug04HopCycleIsRejectedDuringAnalysis(t *testing.T) {
	repository, err := store.Open(filepath.Join(t.TempDir(), "hop-cycle.db"))
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
	hops := []model.Hop{
		{SampleID: sample.ID, Sequence: 1, FromDomain: "edge.example.net", ByDomain: "relay.example.net", ClientIP: "192.0.2.10"},
		{SampleID: sample.ID, Sequence: 2, FromDomain: "relay.example.net", ByDomain: "mx.example.com", ClientIP: "192.0.2.10"},
		{SampleID: sample.ID, Sequence: 3, FromDomain: "mx.example.com", ByDomain: "relay.example.net", ClientIP: "192.0.2.10"},
	}
	for _, hop := range hops {
		if _, err = svc.AddHop(ctx, hop); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = svc.Analyze(ctx, sample.ID, "missing.example.com", "s1"); err == nil {
		t.Fatal("cyclic Received chain was analyzed successfully")
	}
}
