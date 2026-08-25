package domain

import (
	"fmt"
	"net"
	"strings"
)

func Normalize(value string) (string, error) {
	value = strings.TrimSpace(strings.TrimSuffix(strings.ToLower(value), "."))
	if value == "" || len(value) > 253 || strings.Contains(value, "..") {
		return "", fmt.Errorf("invalid domain %q", value)
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid domain %q", value)
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return "", fmt.Errorf("invalid domain %q", value)
			}
		}
	}
	return value, nil
}

func MailboxDomain(address string) (string, error) {
	parts := strings.Split(strings.TrimSpace(address), "@")
	if len(parts) != 2 || parts[0] == "" {
		return "", fmt.Errorf("invalid mailbox")
	}
	return Normalize(parts[1])
}

func OrgDomain(value string) string {
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return value
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func Same(valueA, valueB string, relaxed bool) bool {
	if relaxed {
		return OrgDomain(valueA) == OrgDomain(valueB)
	}
	return valueA == valueB
}

func ValidIP(value string) bool { return net.ParseIP(value) != nil }
