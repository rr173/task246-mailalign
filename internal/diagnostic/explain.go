package diagnostic

import "task246-mailalign/internal/model"

func IsPositive(value model.DiagnosticStatus) bool {
	return value == model.DiagnosticAligned
}

func RequiresReview(value model.DiagnosticStatus) bool {
	return value == model.DiagnosticMisaligned || value == model.DiagnosticInconclusive
}
