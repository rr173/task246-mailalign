package spf

import (
	"testing"

	"task246-mailalign/internal/model"
)

func TestEvaluateIncludeAndLoop(t *testing.T) {
	records := Resolver{
		"example.com":       {Domain: "example.com", Status: model.RecordActive, Mechanisms: []string{"include:relay.example.com", "-all"}},
		"relay.example.com": {Domain: "relay.example.com", Status: model.RecordActive, Mechanisms: []string{"ip4:192.0.2.0/24"}},
	}
	result := Evaluate(records, "example.com", "192.0.2.4")
	if result.Status != "pass" || result.Matched != "include:relay.example.com" {
		t.Fatalf("unexpected SPF result: %+v", result)
	}
	records["relay.example.com"] = model.SPFRecord{Domain: "relay.example.com", Status: model.RecordActive, Mechanisms: []string{"include:example.com"}}
	if result := Evaluate(records, "example.com", "192.0.2.4"); result.Status != "permerror" {
		t.Fatalf("expected include loop, got %+v", result)
	}
}
