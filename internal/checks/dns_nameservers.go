package checks

import (
	"context"

	"github.com/kolisko/domain-score/internal/audit"
)

type DNSNameservers struct{}

func (DNSNameservers) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "dns.nameservers", Title: "Autoritativní nameservery", Category: "dns", Mode: audit.ModeSafe, Weight: 4, Severity: audit.SeverityHigh, Tags: []string{"dns"}}
}

func (c DNSNameservers) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if len(ev.DNS.NS) < 2 {
		return fail(c.Meta(), map[string]any{"ns": ev.DNS.NS}, "Použijte alespoň dva autoritativní nameservery pro redundanci.", c.Meta().Weight)
	}
	return pass(c.Meta(), map[string]any{"ns": ev.DNS.NS}, "")
}
