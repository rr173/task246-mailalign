package dkim

import (
	"testing"

	"task246-mailalign/internal/model"
)

func TestCanonicalBodyAndSelectorValidation(t *testing.T) {
	body := "hello\n\n"
	record := &model.DKIMRecord{Domain: "example.com", Selector: "mail-2026", Status: model.RecordActive, BodySHA: BodySHA(body)}
	if result := Verify(body, record); result.Status != "pass" {
		t.Fatalf("expected pass: %+v", result)
	}
	if result := Verify(body+"x", record); result.Status != "fail" {
		t.Fatalf("expected fail: %+v", result)
	}
	if err := ValidateSelector("bad selector"); err == nil {
		t.Fatal("expected invalid selector")
	}
}
