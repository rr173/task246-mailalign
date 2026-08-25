package chain

import (
	"errors"
	"testing"

	"task246-mailalign/internal/model"
)

func TestValidateRejectsHostLoop(t *testing.T) {
	cases := []struct {
		name string
		hops []model.Hop
	}{
		{
			name: "two-hop back edge",
			hops: []model.Hop{
				{Sequence: 1, FromDomain: "edge.example.net", ByDomain: "mx.example.com", ClientIP: "203.0.113.7"},
				{Sequence: 2, FromDomain: "mx.example.com", ByDomain: "edge.example.net", ClientIP: "203.0.113.7"},
			},
		},
		{
			name: "longer cycle",
			hops: []model.Hop{
				{Sequence: 1, FromDomain: "a.example.net", ByDomain: "b.example.net", ClientIP: "203.0.113.7"},
				{Sequence: 2, FromDomain: "b.example.net", ByDomain: "c.example.net", ClientIP: "203.0.113.7"},
				{Sequence: 3, FromDomain: "c.example.net", ByDomain: "a.example.net", ClientIP: "203.0.113.7"},
			},
		},
		{
			name: "case-insensitive revisit",
			hops: []model.Hop{
				{Sequence: 1, FromDomain: "Edge.Example.Net", ByDomain: "mx.example.com", ClientIP: "203.0.113.7"},
				{Sequence: 2, FromDomain: "mx.example.com", ByDomain: "edge.example.net", ClientIP: "203.0.113.7"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.hops)
			if err == nil {
				t.Fatalf("expected host loop to be rejected, but Validate accepted the chain")
			}
			if !errors.Is(err, ErrHostLoop) {
				t.Fatalf("expected ErrHostLoop, got %v", err)
			}
		})
	}
}

func TestValidateAcceptsAcyclicChain(t *testing.T) {
	hops := []model.Hop{
		{Sequence: 1, FromDomain: "edge.example.net", ByDomain: "mx.example.com", ClientIP: "203.0.113.7"},
		{Sequence: 2, FromDomain: "mx.example.com", ByDomain: "relay.example.com", ClientIP: "203.0.113.7"},
	}
	if err := Validate(hops); err != nil {
		t.Fatalf("expected acyclic chain to be accepted, got %v", err)
	}
}

func TestValidateStillRejectsNonContiguousAndDiscontinuous(t *testing.T) {
	hops := []model.Hop{
		{Sequence: 1, FromDomain: "edge.example.net", ByDomain: "mx.example.com", ClientIP: "203.0.113.7"},
		{Sequence: 3, FromDomain: "mx.example.com", ByDomain: "relay.example.com", ClientIP: "203.0.113.7"},
	}
	if err := Validate(hops); err == nil {
		t.Fatalf("expected non-contiguous sequence to be rejected")
	}
}
