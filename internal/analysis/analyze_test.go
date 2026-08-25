package analysis

import (
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
