package analysis

import (
	"fmt"
	"sort"

	"task246-mailalign/internal/domain"
	"task246-mailalign/internal/model"
)

type ScoreCard struct {
	RiskLevel      string
	Score          int
	AuthMethods    int
	DomainRelation string
	NextActions    []string
}

func BuildScoreCard(sample model.MessageSample, result *model.Diagnostic, items []model.EvidenceItem) ScoreCard {
	score := EvidenceScore(items)
	authMethods := countPassing(result)
	from, _ := domain.MailboxDomain(sample.VisibleFrom)
	relation := relationName(from, result)
	level := riskLevel(result, score, authMethods)
	return ScoreCard{RiskLevel: level, Score: score, AuthMethods: authMethods, DomainRelation: relation, NextActions: actionsFor(result, level)}
}

func countPassing(result *model.Diagnostic) int {
	count := 0
	if result.SPF.Status == "pass" {
		count++
	}
	if result.DKIM.Status == "pass" {
		count++
	}
	return count
}

func relationName(from string, result *model.Diagnostic) string {
	if result.StrictAligned {
		return "strict"
	}
	if result.RelaxedAligned {
		return "relaxed"
	}
	if result.DKIM.Status == "pass" || result.SPF.Status == "pass" {
		return "authenticated-but-unmatched"
	}
	return "unknown"
}

func riskLevel(result *model.Diagnostic, score, authMethods int) string {
	if result.Status == model.DiagnosticInconclusive {
		return "high"
	}
	if result.StrictAligned && authMethods >= 1 && score >= 4 {
		return "low"
	}
	if result.RelaxedAligned && authMethods >= 1 && score >= 2 {
		return "medium"
	}
	return "high"
}

func actionsFor(result *model.Diagnostic, level string) []string {
	actions := make([]string, 0, 5)
	if result.SPF.Status != "pass" {
		actions = append(actions, "capture the SPF record used by the receiving hop")
	}
	if result.DKIM.Status != "pass" {
		actions = append(actions, "recheck the DKIM selector snapshot and canonical body")
	}
	if result.RelaxedAligned && !result.StrictAligned {
		actions = append(actions, "confirm that organizational-domain relaxation is intended")
	}
	if len(result.TrustedHops) == 0 {
		actions = append(actions, "review whether an intermediate relay should be marked trusted")
	}
	if level == "high" {
		actions = append(actions, "do not publish the diagnostic as a clean alignment result")
	}
	if len(actions) == 0 {
		actions = append(actions, "retain the DNS snapshots with the published diagnostic")
	}
	return uniqueStrings(actions)
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			result = append(result, value)
			seen[value] = true
		}
	}
	return result
}

func SortEvidence(items []model.EvidenceItem) []model.EvidenceItem {
	result := append([]model.EvidenceItem(nil), items...)
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Weight != result[j].Weight {
			return result[i].Weight > result[j].Weight
		}
		if result[i].Kind != result[j].Kind {
			return result[i].Kind < result[j].Kind
		}
		return result[i].Subject < result[j].Subject
	})
	return result
}

func ScoreLabel(score int) string {
	switch {
	case score >= 6:
		return "strong"
	case score >= 2:
		return "partial"
	case score >= 0:
		return "weak"
	default:
		return "negative"
	}
}

func FormatScore(card ScoreCard) string {
	return fmt.Sprintf("risk=%s score=%d auth_methods=%d relation=%s", card.RiskLevel, card.Score, card.AuthMethods, card.DomainRelation)
}

func HasBlockingAction(card ScoreCard) bool {
	for _, action := range card.NextActions {
		if action == "do not publish the diagnostic as a clean alignment result" {
			return true
		}
	}
	return false
}

func ExplainRisk(card ScoreCard) string {
	if card.RiskLevel == "low" {
		return "at least one authentication method passed and strict alignment is available"
	}
	if card.RiskLevel == "medium" {
		return "authentication passed only under relaxed organizational-domain comparison"
	}
	return "the available authentication evidence does not establish a publishable alignment"
}

func RiskRank(level string) int {
	switch level {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	default:
		return 4
	}
}

func IsPublishable(card ScoreCard) bool { return card.RiskLevel == "low" || card.RiskLevel == "medium" }

func OutcomePenalty(outcome string) int {
	switch outcome {
	case "pass", "strict", "relaxed":
		return 0
	case "neutral", "softfail", "review":
		return 1
	case "fail", "none", "missing":
		return 3
	default:
		return 2
	}
}
