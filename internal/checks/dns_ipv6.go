package checks

import (
	"context"

	"github.com/kolisko/domain-score/internal/audit"
)

type DNSIPv6 struct{}

func (DNSIPv6) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "dns.ipv6", Title: "IPv6 AAAA záznam", Category: "dns", Mode: audit.ModeSafe, Weight: 2, Severity: audit.SeverityLow, Tags: []string{"dns", "ipv6"}}
}

func (c DNSIPv6) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if len(ev.DNS.AAAA) == 0 {
		return warn(c.Meta(), nil, "Zvažte přidání IPv6 dostupnosti přes AAAA záznam.", 1)
	}
	return pass(c.Meta(), map[string]any{"aaaa": ev.DNS.AAAA}, "")
}
