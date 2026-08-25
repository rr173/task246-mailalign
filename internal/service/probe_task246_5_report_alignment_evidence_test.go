package service

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"task246-mailalign/internal/dkim"
	"task246-mailalign/internal/model"
	"task246-mailalign/internal/store"
)

func TestBug05ReportExplainsThePassingAlignedMethod(t *testing.T) {
	repository, err := store.Open(filepath.Join(t.TempDir(), "report-evidence.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	svc := New(repository)
	ctx := context.Background()
	body := "message"
	if _, err = svc.SaveSPF(ctx, model.SPFRecord{Domain: "mx.example.net", Version: 1, Mechanisms: []string{"ip4:192.0.2.0/24"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.SaveDKIM(ctx, model.DKIMRecord{Domain: "corp.example.com", Selector: "s1", Version: 1, BodySHA: dkim.BodySHA(body)}); err != nil {
		t.Fatal(err)
	}
	sample, _, err := svc.CreateSample(ctx, model.MessageSample{VisibleFrom: "a@corp.example.com", ReturnPath: "b@mx.example.net", RecipientIP: "192.0.2.10", Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Analyze(ctx, sample.ID, "corp.example.com", "s1"); err != nil {
		t.Fatal(err)
	}
	report, err := svc.Report(ctx, sample.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range report.Evidence {
		if item.Kind == "alignment" {
			want := "corp.example.com and corp.example.com are identical domains"
			if !strings.Contains(item.Detail, want) {
				t.Fatalf("alignment evidence followed failing SPF instead of aligned DKIM: %q", item.Detail)
			}
			return
		}
	}
	t.Fatal("alignment evidence was not emitted")
}
