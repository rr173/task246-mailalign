package domain

import "testing"

func TestParentAndOrganizationDomains(t *testing.T) {
	value, err := Normalize("Mail.Example.COM.")
	if err != nil {
		t.Fatal(err)
	}
	if value != "mail.example.com" {
		t.Fatalf("unexpected normalized domain %q", value)
	}
	parents := ParentDomains(value)
	if len(parents) != 3 || parents[1] != "example.com" {
		t.Fatalf("unexpected parents %#v", parents)
	}
	if !Same("a.corp.example.com", "b.mx.example.com", true) || Same("a.corp.example.com", "b.mx.example.com", false) {
		t.Fatal("strict/relaxed comparison mismatch")
	}
}
