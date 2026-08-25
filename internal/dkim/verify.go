package dkim

import (
	"crypto/sha256"
	"encoding/hex"

	"task246-mailalign/internal/canonical"
	"task246-mailalign/internal/model"
)

func BodySHA(body string) string {
	digest := sha256.Sum256([]byte(canonical.Body(body)))
	return hex.EncodeToString(digest[:])
}

func Verify(body string, record *model.DKIMRecord) model.DKIMResult {
	result := model.DKIMResult{Status: "none"}
	if record == nil {
		result.Explanation = "DKIM selector record is missing"
		return result
	}
	result.Domain, result.Selector, result.ExpectedSHA = record.Domain, record.Selector, record.BodySHA
	result.ActualSHA = BodySHA(body)
	if record.Status != model.RecordActive {
		result.Status = "tempfail"
		result.Explanation = "DKIM selector record is not active"
		return result
	}
	if result.ExpectedSHA != result.ActualSHA {
		result.Status = "fail"
		result.Explanation = "canonical body hash does not match selector snapshot"
		return result
	}
	result.Status = "pass"
	result.Explanation = "canonical body hash matched selector snapshot"
	return result
}
