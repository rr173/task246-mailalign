package analysis

import (
	"sort"
	"strings"

	"task246-mailalign/internal/model"
)

// NormalizeEvidence removes empty facts and makes report ordering deterministic.
func NormalizeEvidence(values []model.EvidenceItem) []model.EvidenceItem {
	result := make([]model.EvidenceItem, 0, len(values))
	for _, value := range values {
		value.Kind = strings.TrimSpace(strings.ToLower(value.Kind))
		value.Subject = strings.TrimSpace(value.Subject)
		value.Outcome = strings.TrimSpace(strings.ToLower(value.Outcome))
		value.Detail = strings.TrimSpace(value.Detail)
		if value.Kind == "" || value.Subject == "" {
			continue
		}
		result = append(result, value)
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Kind != result[j].Kind {
			return result[i].Kind < result[j].Kind
		}
		return result[i].Subject < result[j].Subject
	})
	return result
}

func OutcomeCounts(values []model.EvidenceItem) map[string]int {
	counts := map[string]int{}
	for _, value := range values {
		counts[value.Outcome]++
	}
	return counts
}

func HasOutcome(values []model.EvidenceItem, outcome string) bool {
	for _, value := range values {
		if strings.EqualFold(value.Outcome, outcome) {
			return true
		}
	}
	return false
}
