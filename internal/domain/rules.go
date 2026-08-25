package domain

import "fmt"

type AlignmentMode string

const (
	StrictMode  AlignmentMode = "strict"
	RelaxedMode AlignmentMode = "relaxed"
)

func CompareModes(left, right string) map[AlignmentMode]bool {
	return map[AlignmentMode]bool{StrictMode: Same(left, right, false), RelaxedMode: Same(left, right, true)}
}

func AlignmentExplanation(left, right string, strict, relaxed bool) string {
	switch {
	case strict:
		return fmt.Sprintf("%s and %s are identical domains", left, right)
	case relaxed:
		return fmt.Sprintf("%s and %s share organization %s", left, right, SharedOrg(left, right))
	default:
		return fmt.Sprintf("%s and %s do not share an aligned organization", left, right)
	}
}

func ParentForPolicy(value string) string {
	parents := ParentDomains(value)
	if len(parents) > 1 {
		return parents[1]
	}
	return value
}
