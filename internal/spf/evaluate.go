package spf

import (
	"fmt"
	"net"
	"strings"

	"task246-mailalign/internal/model"
)

type Resolver map[string]model.SPFRecord

func Evaluate(records Resolver, domain, clientIP string) model.SPFResult {
	result := model.SPFResult{Domain: domain, ClientIP: clientIP, Status: "none", Trace: []string{domain}}
	if net.ParseIP(clientIP) == nil {
		result.Status, result.Explanation = "fail", "client IP is invalid"
		return result
	}
	status, matched, trace, err := evaluate(records, domain, clientIP, nil, 0)
	result.Status, result.Matched, result.Trace = status, matched, trace
	if err != nil {
		result.Status = "permerror"
		result.Explanation = err.Error()
	} else if matched != "" {
		result.Explanation = "client IP matched SPF mechanism"
	} else {
		result.Explanation = "no SPF mechanism matched"
	}
	return result
}

func evaluate(records Resolver, domain, clientIP string, seen map[string]bool, depth int) (string, string, []string, error) {
	if depth > 8 {
		return "permerror", "", nil, fmt.Errorf("SPF include depth exceeded")
	}
	if seen == nil {
		seen = map[string]bool{}
	}
	if seen[domain] {
		return "permerror", "", nil, fmt.Errorf("SPF include loop at %s", domain)
	}
	seen[domain] = true
	// Only the domains on the current recursion path constitute a loop. A
	// forwarding domain may be referenced more than once by sibling include
	// mechanisms in the same record; after a child evaluation returns it must
	// be eligible for re-evaluation, so undo the visit on the way out.
	defer delete(seen, domain)
	record, ok := records[domain]
	if !ok || record.Status != model.RecordActive {
		return "none", "", []string{domain}, nil
	}
	trace := []string{domain}
	for _, mechanism := range record.Mechanisms {
		mechanism = strings.TrimSpace(strings.ToLower(mechanism))
		switch {
		case strings.HasPrefix(mechanism, "ip4:"):
			_, network, err := net.ParseCIDR(strings.TrimPrefix(mechanism, "ip4:"))
			if err != nil {
				return "permerror", "", trace, fmt.Errorf("invalid SPF ip4 mechanism")
			}
			if network.Contains(net.ParseIP(clientIP)) {
				return "pass", mechanism, trace, nil
			}
		case strings.HasPrefix(mechanism, "ip6:"):
			_, network, err := net.ParseCIDR(strings.TrimPrefix(mechanism, "ip6:"))
			if err != nil {
				return "permerror", "", trace, fmt.Errorf("invalid SPF ip6 mechanism")
			}
			if network.Contains(net.ParseIP(clientIP)) {
				return "pass", mechanism, trace, nil
			}
		case strings.HasPrefix(mechanism, "include:"):
			child := strings.TrimPrefix(mechanism, "include:")
			status, matched, childTrace, err := evaluate(records, child, clientIP, seen, depth+1)
			trace = append(trace, childTrace...)
			if err != nil {
				return status, matched, trace, err
			}
			if status == "pass" {
				return "pass", mechanism, trace, nil
			}
		case mechanism == "-all":
			return "fail", mechanism, trace, nil
		case mechanism == "~all":
			return "softfail", mechanism, trace, nil
		case mechanism == "?all":
			return "neutral", mechanism, trace, nil
		case mechanism == "+all":
			return "pass", mechanism, trace, nil
		}
	}
	return "neutral", "", trace, nil
}
