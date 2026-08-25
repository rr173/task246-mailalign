package service

import (
	"context"
	"path/filepath"
	"testing"

	"task246-mailalign/internal/dkim"
	"task246-mailalign/internal/model"
	"task246-mailalign/internal/store"
)

func TestBug10DKIMDomainInputIsNormalizedBeforeLookup(t *testing.T) {
	repository, err := store.Open(filepath.Join(t.TempDir(), "dkim-domain.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	svc := New(repository)
	ctx := context.Background()
	body := "message"
	if _, err = svc.SaveSPF(ctx, model.SPFRecord{Domain: "mx.example.net", Version: 1, Mechanisms: []string{"-all"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.SaveDKIM(ctx, model.DKIMRecord{Domain: "signed.example.com", Selector: "s1", Version: 1, BodySHA: dkim.BodySHA(body)}); err != nil {
		t.Fatal(err)
	}
	sample, _, err := svc.CreateSample(ctx, model.MessageSample{VisibleFrom: "a@corp.example.com", ReturnPath: "b@mx.example.net", RecipientIP: "192.0.2.10", Body: body})
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.Analyze(ctx, sample.ID, "SIGNED.EXAMPLE.COM", "s1")
	if err != nil {
		t.Fatal(err)
	}
	if result.DKIM.Status != "pass" {
		t.Fatalf("uppercase DKIM domain failed selector lookup: %+v", result.DKIM)
	}
}
