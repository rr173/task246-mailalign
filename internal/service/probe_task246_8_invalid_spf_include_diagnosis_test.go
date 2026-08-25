package service

import (
	"context"
	"path/filepath"
	"testing"

	"task246-mailalign/internal/model"
	"task246-mailalign/internal/store"
)

func TestBug08InvalidSPFIncludeShouldBeRejected(t *testing.T) {
	repository, err := store.Open(filepath.Join(t.TempDir(), "invalid-spf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	svc := New(repository)
	if _, err = svc.SaveSPF(context.Background(), model.SPFRecord{Domain: "sender.example.com", Version: 1, Mechanisms: []string{"include:not a domain", "-all"}}); err == nil {
		t.Fatal("invalid SPF include was accepted")
	}
}
