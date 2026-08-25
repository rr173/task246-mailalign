package service

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"task246-mailalign/internal/model"
	"task246-mailalign/internal/store"
)

func TestBug01RepeatedSPFIncludeDoesNotBecomeLoop(t *testing.T) {
	repository, err := store.Open(filepath.Join(t.TempDir(), "spf-repeat.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	svc := New(repository)
	ctx := context.Background()
	if _, err = svc.SaveSPF(ctx, model.SPFRecord{Domain: "sender.example.com", Version: 1, Mechanisms: []string{"include:relay.example.com", "include:relay.example.com", "-all"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.SaveSPF(ctx, model.SPFRecord{Domain: "relay.example.com", Version: 1, Mechanisms: []string{"-all"}}); err != nil {
		t.Fatal(err)
	}
	sample, _, err := svc.CreateSample(ctx, model.MessageSample{VisibleFrom: "a@corp.example.com", ReturnPath: "b@sender.example.com", RecipientIP: "192.0.2.10", Body: "message"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.Analyze(ctx, sample.ID, "missing.example.com", "s1")
	if err != nil {
		t.Fatal(err)
	}
	if result.SPF.Status != "fail" || strings.Contains(result.SPF.Explanation, "loop") {
		t.Fatalf("repeated non-passing include was misclassified: %+v", result.SPF)
	}
}
