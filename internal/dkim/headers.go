package dkim

import (
	"fmt"
	"regexp"
	"strings"
)

var selectorPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

func ValidateSelector(value string) error {
	if !selectorPattern.MatchString(strings.ToLower(value)) {
		return fmt.Errorf("invalid DKIM selector")
	}
	return nil
}

func NormalizeHeaderNames(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" && !seen[value] {
			result = append(result, value)
			seen[value] = true
		}
	}
	return result
}

func SignedHeaderPresent(values []string, name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, value := range NormalizeHeaderNames(values) {
		if value == name {
			return true
		}
	}
	return false
}
