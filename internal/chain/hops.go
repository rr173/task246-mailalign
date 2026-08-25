package chain

import (
	"fmt"

	"task246-mailalign/internal/model"
)

func Validate(hops []model.Hop) error {
	seen := map[string]bool{}
	for index, hop := range hops {
		if hop.Sequence != index+1 {
			return fmt.Errorf("hop sequence must be contiguous at %d", hop.Sequence)
		}
		key := hop.FromDomain + "->" + hop.ByDomain
		if seen[key] {
			return fmt.Errorf("repeated hop chain %s", key)
		}
		seen[key] = true
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
