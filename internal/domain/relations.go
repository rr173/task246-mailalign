package domain

import "strings"

func Labels(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ".")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func ParentDomains(value string) []string {
	labels := Labels(value)
	result := make([]string, 0, len(labels))
	for i := range labels {
		result = append(result, strings.Join(labels[i:], "."))
	}
	return result
}

func IsSubdomain(child, parent string) bool {
	child, parent = strings.ToLower(strings.TrimSuffix(child, ".")), strings.ToLower(strings.TrimSuffix(parent, "."))
	return child != parent && strings.HasSuffix(child, "."+parent)
}

func SharedOrg(domains ...string) string {
	if len(domains) == 0 {
		return ""
	}
	base := OrgDomain(domains[0])
	for _, value := range domains[1:] {
		if OrgDomain(value) != base {
			return ""
		}
	}
	return base
}
