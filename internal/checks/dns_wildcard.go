package checks

import (
	"context"

	"github.com/kolisko/domain-score/internal/audit"
)

type DNSWildcard struct{}

func (DNSWildcard) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "dns.wildcard", Title: "Wildcard DNS kontrola", Category: "dns", Mode: audit.ModeSafe, Weight: 2, Severity: audit.SeverityLow, Tags: []string{"dns"}}
}

func (c DNSWildcard) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if len(ev.DNS.WildcardA) > 0 {
		return warn(c.Meta(), map[string]any{"wildcard_a": ev.DNS.WildcardA}, "Wildcard DNS může skrývat překlepy a zhoršit takeover heuristiky; používejte ho jen záměrně.", 1)
	}
	return pass(c.Meta(), nil, "")
}
