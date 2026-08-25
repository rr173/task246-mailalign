package spf

import (
	"fmt"
	"net"
	"strings"
)

func ValidateMechanisms(values []string) error {
	if len(values) == 0 {
		return fmt.Errorf("SPF mechanism list is empty")
	}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			return fmt.Errorf("empty SPF mechanism")
		}
		if strings.HasPrefix(value, "ip4:") || strings.HasPrefix(value, "ip6:") {
			if _, _, err := net.ParseCIDR(strings.SplitN(value, ":", 2)[1]); err != nil {
				return fmt.Errorf("invalid network in %s", value)
			}
			continue
		}
		if strings.HasPrefix(value, "include:") || strings.HasPrefix(value, "a:") || strings.HasPrefix(value, "mx:") {
			if len(strings.SplitN(value, ":", 2)[1]) < 3 {
				return fmt.Errorf("invalid domain mechanism %s", value)
			}
			continue
		}
		if value == "-all" || value == "~all" || value == "+all" || value == "?all" {
			continue
		}
		return fmt.Errorf("unsupported SPF mechanism %s", value)
	}
	return nil
}

func MechanismName(value string) string {
	value = strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(value, "+"), "-"), "~"), "?")
	if index := strings.IndexByte(value, ':'); index >= 0 {
		return value[:index]
	}
	if index := strings.IndexByte(value, '='); index >= 0 {
		return value[:index]
	}
	return value
}
