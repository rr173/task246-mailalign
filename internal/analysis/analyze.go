package analysis

import (
	"fmt"

	"task246-mailalign/internal/chain"
	"task246-mailalign/internal/dkim"
	"task246-mailalign/internal/domain"
	"task246-mailalign/internal/model"
	"task246-mailalign/internal/spf"
)

type Input struct {
	Sample     model.MessageSample
	Hops       []model.Hop
	SPF        map[string]model.SPFRecord
	DKIM       map[string]model.DKIMRecord
	DKIMDomain string
	Selector   string
}

func Run(input Input) (*model.Diagnostic, error) {
	fromDomain, err := domain.MailboxDomain(input.Sample.VisibleFrom)
	if err != nil {
		return nil, fmt.Errorf("from: %w", err)
	}
	returnDomain, err := domain.MailboxDomain(input.Sample.ReturnPath)
	if err != nil {
		return nil, fmt.Errorf("return path: %w", err)
	}
	if err := chain.Validate(input.Hops); err != nil {
		return nil, err
	}
	spfResult := spf.Evaluate(input.SPF, returnDomain, input.Sample.RecipientIP)
	var dkimRecord *model.DKIMRecord
	if record, ok := input.DKIM[input.DKIMDomain+":"+input.Selector]; ok {
		copy := record
		dkimRecord = &copy
	}
	dkimResult := dkim.Verify(input.Sample.Body, dkimRecord)
	spfStrict := spfResult.Status == "pass" && domain.Same(returnDomain, fromDomain, false)
	spfRelaxed := spfResult.Status == "pass" && domain.Same(returnDomain, fromDomain, true)
	dkimStrict := dkimResult.Status == "pass" && domain.Same(dkimResult.Domain, fromDomain, false)
	dkimRelaxed := dkimResult.Status == "pass" && domain.Same(dkimResult.Domain, fromDomain, true)
	strict := spfStrict || dkimStrict
	relaxed := spfRelaxed || dkimRelaxed
	status := model.DiagnosticMisaligned
	if strict {
		status = model.DiagnosticAligned
	} else if relaxed {
		status = model.DiagnosticAligned
	}
	if spfResult.Status == "none" && dkimResult.Status == "none" {
		status = model.DiagnosticInconclusive
	}
	explanation := []string{fmt.Sprintf("SPF %s for %s", spfResult.Status, returnDomain), fmt.Sprintf("DKIM %s for %s", dkimResult.Status, dkimResult.Domain)}
	if relaxed && !strict {
		explanation = append(explanation, "alignment is available only under relaxed organizational-domain comparison")
	}
	return &model.Diagnostic{
		SampleID: input.Sample.ID, Status: status, SPF: spfResult, DKIM: dkimResult,
		StrictAligned: strict, RelaxedAligned: relaxed, TrustedHops: chain.Trusted(input.Hops), HopPath: chain.Path(input.Hops), Explanation: explanation,
	}, nil
}
