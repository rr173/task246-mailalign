package chain

import (
	"fmt"
	"strings"

	"task246-mailalign/internal/model"
)

func Path(hops []model.Hop) []string {
	result := make([]string, 0, len(hops)*2)
	for _, hop := range hops {
		if len(result) == 0 {
			result = append(result, hop.FromDomain)
		}
		result = append(result, hop.ByDomain)
	}
	return result
}

func ValidateContinuity(hops []model.Hop) error {
	for index := 1; index < len(hops); index++ {
		if !strings.EqualFold(hops[index-1].ByDomain, hops[index].FromDomain) {
			return fmt.Errorf("hop %d does not continue from %s", hops[index].Sequence, hops[index-1].ByDomain)
		}
	}
	return nil
}

func ContainsDomain(hops []model.Hop, value string) bool {
	for _, hop := range hops {
		if hop.FromDomain == value || hop.ByDomain == value {
			return true
		}
	}
	return false
}
