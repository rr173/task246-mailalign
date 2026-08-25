package service

import (
	"context"
	"path/filepath"
	"testing"

	"task246-mailalign/internal/model"
	"task246-mailalign/internal/store"
)

func TestBug02HighestSPFVersionRemainsAuthoritative(t *testing.T) {
	repository, err := store.Open(filepath.Join(t.TempDir(), "spf-version.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	svc := New(repository)
	ctx := context.Background()
	if _, err = svc.SaveSPF(ctx, model.SPFRecord{Domain: "sender.example.com", Version: 2, Mechanisms: []string{"ip4:192.0.2.0/24", "-all"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.SaveSPF(ctx, model.SPFRecord{Domain: "sender.example.com", Version: 1, Mechanisms: []string{"-all"}}); err != nil {
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
	if result.SPF.Status != "pass" || result.SPF.Matched != "ip4:192.0.2.0/24" {
		t.Fatalf("older SPF snapshot overrode version 2: %+v", result.SPF)
	}
}
