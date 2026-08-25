package analysis

import (
	"strings"
	"testing"

	"task246-mailalign/internal/dkim"
	"task246-mailalign/internal/model"
)

func TestRunDistinguishesStrictAndRelaxedAlignment(t *testing.T) {
	body := "hello"
	result, err := Run(Input{
		Sample:     model.MessageSample{ID: 1, VisibleFrom: "a@corp.example.com", ReturnPath: "b@mx.example.com", RecipientIP: "203.0.113.8", Body: body},
		Hops:       []model.Hop{{ID: 2, Sequence: 1, FromDomain: "edge.example.net", ByDomain: "mx.example.com", ClientIP: "203.0.113.8"}},
		SPF:        map[string]model.SPFRecord{"mx.example.com": {Domain: "mx.example.com", Status: model.RecordActive, Mechanisms: []string{"ip4:203.0.113.0/24"}}},
		DKIM:       map[string]model.DKIMRecord{"signed.example.com:s1": {Domain: "signed.example.com", Selector: "s1", Status: model.RecordActive, BodySHA: dkim.BodySHA(body)}},
		DKIMDomain: "signed.example.com", Selector: "s1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.RelaxedAligned || result.StrictAligned || result.DKIM.Status != "pass" {
		t.Fatalf("unexpected alignment: %+v", result)
	}
}

// TestAlignmentDetailExplainsAlignedDKIMOverUnalignedSPF guards the report
// against the regression where a passing-but-unaligned SPF result shadows a
// DKIM result that genuinely aligns with the visible From domain.
func TestAlignmentDetailExplainsAlignedDKIMOverUnalignedSPF(t *testing.T) {
	body := "hello"
	result, err := Run(Input{
		// Visible From (corp.example.com) and the DKIM signing domain
		// (signed.example.com) share the example.com organization, so DKIM is
		// relaxed-aligned. The Return-Path / SPF domain (mail.otherorg.net)
		// sits in an unrelated organization and is NOT aligned even though SPF
		// passes for it.
		Sample:     model.MessageSample{ID: 1, VisibleFrom: "a@corp.example.com", ReturnPath: "b@mail.otherorg.net", RecipientIP: "203.0.113.8", Body: body},
		Hops:       []model.Hop{{ID: 2, Sequence: 1, FromDomain: "edge.example.net", ByDomain: "mx.example.com", ClientIP: "203.0.113.8"}},
		SPF:        map[string]model.SPFRecord{"mail.otherorg.net": {Domain: "mail.otherorg.net", Status: model.RecordActive, Mechanisms: []string{"ip4:203.0.113.0/24"}}},
		DKIM:       map[string]model.DKIMRecord{"signed.example.com:s1": {Domain: "signed.example.com", Selector: "s1", Status: model.RecordActive, BodySHA: dkim.BodySHA(body)}},
		DKIMDomain: "signed.example.com", Selector: "s1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.SPF.Status != "pass" || result.DKIM.Status != "pass" {
		t.Fatalf("expected both SPF and DKIM to pass: spf=%s dkim=%s", result.SPF.Status, result.DKIM.Status)
	}
	if !result.RelaxedAligned || result.StrictAligned {
		t.Fatalf("expected relaxed-only alignment: %+v", result)
	}
	items := Evidence(Input{
		Sample: model.MessageSample{ID: 1, VisibleFrom: "a@corp.example.com", ReturnPath: "b@mail.otherorg.net", RecipientIP: "203.0.113.8", Body: body},
		Hops:   []model.Hop{{ID: 2, Sequence: 1, FromDomain: "edge.example.net", ByDomain: "mx.example.com", ClientIP: "203.0.113.8"}},
	}, result)
	var detail string
	for _, item := range items {
		if item.Kind == "alignment" {
			detail = item.Detail
		}
	}
	if detail == "" {
		t.Fatal("missing alignment evidence detail")
	}
	if !strings.Contains(detail, "signed.example.com") {
		t.Fatalf("alignment detail should explain the aligned DKIM domain, got %q", detail)
	}
	if strings.Contains(detail, "otherorg.net") {
		t.Fatalf("alignment detail must not be shadowed by the unaligned SPF domain, got %q", detail)
	}
}
