package analysis

import (
	"fmt"
	"strings"

	"task246-mailalign/internal/domain"
	"task246-mailalign/internal/model"
)

// Evidence builds independently inspectable facts for an engineer-facing report.
func Evidence(input Input, result *model.Diagnostic) []model.EvidenceItem {
	return []model.EvidenceItem{
		{Kind: "sample", Subject: input.Sample.MessageKey, Outcome: string(input.Sample.Status), Detail: "message sample was persisted before analysis", Weight: 1},
		{Kind: "spf", Subject: result.SPF.Domain, Outcome: result.SPF.Status, Detail: result.SPF.Explanation, Weight: scoreProtocol(result.SPF.Status)},
		{Kind: "dkim", Subject: result.DKIM.Domain + ":" + result.DKIM.Selector, Outcome: result.DKIM.Status, Detail: result.DKIM.Explanation, Weight: scoreProtocol(result.DKIM.Status)},
		{Kind: "hops", Subject: strings.Join(result.HopPath, " -> "), Outcome: hopOutcome(input.Hops), Detail: hopDetail(input.Hops), Weight: hopWeight(input.Hops)},
		{Kind: "alignment", Subject: input.Sample.VisibleFrom, Outcome: alignmentOutcome(result), Detail: alignmentDetail(input.Sample, result), Weight: alignmentWeight(result)},
	}
}

func scoreProtocol(status string) int {
	switch status {
	case "pass":
		return 3
	case "none":
		return 0
	case "neutral", "softfail":
		return 1
	default:
		return -2
	}
}

func hopOutcome(hops []model.Hop) string {
	if len(hops) == 0 {
		return "missing"
	}
	for _, hop := range hops {
		if hop.Status == model.HopRejected || hop.Status == model.HopSuspicious {
			return "review"
		}
	}
	return "observed"
}

func hopDetail(hops []model.Hop) string {
	if len(hops) == 0 {
		return "no Received hop was recorded"
	}
	return fmt.Sprintf("%d ordered hops were recorded", len(hops))
}

func hopWeight(hops []model.Hop) int {
	if len(hops) == 0 {
		return -1
	}
	for _, hop := range hops {
		if hop.Status == model.HopSuspicious || hop.Status == model.HopRejected {
			return -1
		}
	}
	return 1
}

func alignmentOutcome(result *model.Diagnostic) string {
	if result.StrictAligned {
		return "strict"
	}
	if result.RelaxedAligned {
		return "relaxed"
	}
	return "none"
}

func alignmentDetail(sample model.MessageSample, result *model.Diagnostic) string {
	from, _ := domain.MailboxDomain(sample.VisibleFrom)
	if result.SPF.Status == "pass" {
		return domain.AlignmentExplanation(from, result.SPF.Domain, domain.Same(from, result.SPF.Domain, false), domain.Same(from, result.SPF.Domain, true))
	}
	if result.DKIM.Status == "pass" {
		return domain.AlignmentExplanation(from, result.DKIM.Domain, domain.Same(from, result.DKIM.Domain, false), domain.Same(from, result.DKIM.Domain, true))
	}
	return "no passing authentication result supplies an aligned domain"
}

func alignmentWeight(result *model.Diagnostic) int {
	if result.StrictAligned {
		return 4
	}
	if result.RelaxedAligned {
		return 2
	}
	return -3
}

func EvidenceScore(items []model.EvidenceItem) int {
	total := 0
	for _, item := range items {
		total += item.Weight
	}
	return total
}

func EvidenceSummary(result *model.Diagnostic, score int) string {
	if result.StrictAligned {
		return fmt.Sprintf("strict alignment confirmed with evidence score %d", score)
	}
	if result.RelaxedAligned {
		return fmt.Sprintf("relaxed alignment confirmed with evidence score %d", score)
	}
	if result.Status == model.DiagnosticInconclusive {
		return "authentication evidence is insufficient"
	}
	return fmt.Sprintf("authentication domains are misaligned with evidence score %d", score)
}
