package chain

import (
	"errors"
	"fmt"
	"strings"

	"task246-mailalign/internal/model"
)

// ErrHostLoop signals that the Received hop chain revisits a host, i.e. a
// domain that already appeared in the relay path is reached again. Such a
// chain cannot be trusted and must be rejected rather than producing a
// diagnostic.
var ErrHostLoop = errors.New("host loop in received chain")

// Validate rejects malformed and cyclic hop chains. A chain is invalid when
// its hop sequence is not contiguous, when a host is visited more than once
// (a host loop), or when adjacent hops are not continuous.
func Validate(hops []model.Hop) error {
	visited := make(map[string]int, len(hops)*2)
	for index, hop := range hops {
		if hop.Sequence != index+1 {
			return fmt.Errorf("hop sequence must be contiguous at %d", hop.Sequence)
		}
		if index == 0 {
			visited[strings.ToLower(hop.FromDomain)] = hop.Sequence
		}
		host := strings.ToLower(hop.ByDomain)
		if prev, seen := visited[host]; seen {
			return fmt.Errorf("received chain revisits host %s at hop %d (first seen at hop %d): %w", hop.ByDomain, hop.Sequence, prev, ErrHostLoop)
		}
		visited[host] = hop.Sequence
	}
	return ValidateContinuity(hops)
}

func Trusted(hops []model.Hop) []int64 {
	ids := make([]int64, 0)
	for _, hop := range hops {
		if hop.Status == model.HopTrusted {
			ids = append(ids, hop.ID)
		}
	}
	return ids
}
