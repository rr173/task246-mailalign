package store

import (
	"context"
	"path/filepath"
	"testing"

	"task246-mailalign/internal/model"
)

// TestSPFPicksHighestVersion guards against an older snapshot overwriting a newer one
// when several active versions of the same SPF domain coexist. The query returns rows
// in an unspecified order, so the highest version must win regardless of scan order.
func TestSPFPicksHighestVersion(t *testing.T) {
	ctx := context.Background()
	repository, err := Open(filepath.Join(t.TempDir(), "records.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()

	// Insert newest version first so the older v1 row receives a higher row id.
	// Without the highest-version guard, rows scanned later would let v1 overwrite v3.
	if _, err = repository.SaveSPF(ctx, &model.SPFRecord{Domain: "mx.example.com", Version: 3, Mechanisms: []string{"ip4:203.0.113.0/24"}, Status: model.RecordActive}); err != nil {
		t.Fatal(err)
	}
	if _, err = repository.SaveSPF(ctx, &model.SPFRecord{Domain: "mx.example.com", Version: 2, Mechanisms: []string{"ip4:198.51.100.0/24"}, Status: model.RecordActive}); err != nil {
		t.Fatal(err)
	}
	if _, err = repository.SaveSPF(ctx, &model.SPFRecord{Domain: "mx.example.com", Version: 1, Mechanisms: []string{"ip4:192.0.2.0/24"}, Status: model.RecordActive}); err != nil {
		t.Fatal(err)
	}

	records, err := repository.SPF(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := records["mx.example.com"]
	if !ok {
		t.Fatal("missing SPF record")
	}
	if got.Version != 3 {
		t.Fatalf("expected highest version 3, got %d", got.Version)
	}
	if len(got.Mechanisms) != 1 || got.Mechanisms[0] != "ip4:203.0.113.0/24" {
		t.Fatalf("expected the v3 mechanisms to survive, got %+v", got.Mechanisms)
	}
}

// TestDKIMPicksHighestVersion mirrors the SPF guard for domain+selector keyed records.
func TestDKIMPicksHighestVersion(t *testing.T) {
	ctx := context.Background()
	repository, err := Open(filepath.Join(t.TempDir(), "records.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()

	if _, err = repository.SaveDKIM(ctx, &model.DKIMRecord{Domain: "signed.example.com", Selector: "s1", Version: 1, BodySHA: "alpha", Status: model.RecordActive}); err != nil {
		t.Fatal(err)
	}
	if _, err = repository.SaveDKIM(ctx, &model.DKIMRecord{Domain: "signed.example.com", Selector: "s1", Version: 2, BodySHA: "beta", Status: model.RecordActive}); err != nil {
		t.Fatal(err)
	}

	records, err := repository.DKIM(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := records["signed.example.com:s1"]
	if !ok {
		t.Fatal("missing DKIM record")
	}
	if got.Version != 2 {
		t.Fatalf("expected highest version 2, got %d", got.Version)
	}
	if got.BodySHA != "beta" {
		t.Fatalf("expected the v2 body sha to survive, got %s", got.BodySHA)
	}
}
