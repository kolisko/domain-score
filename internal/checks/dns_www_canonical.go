package checks

import (
	"context"

	"github.com/kolisko/domain-score/internal/audit"
)

type DNSWWWCanonical struct{}

func (DNSWWWCanonical) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "dns.www_canonical", Title: "Apex a www jsou dostupné", Category: "dns", Mode: audit.ModeSafe, Weight: 2, Severity: audit.SeverityLow, Tags: []string{"dns", "seo"}}
}

func (c DNSWWWCanonical) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if len(ev.DNS.WWWAddress) == 0 {
		return warn(c.Meta(), nil, "Nastavte `www` hostname nebo z něj jasně přesměrujte na kanonickou doménu.", 1)
	}
	return pass(c.Meta(), map[string]any{"www_address": ev.DNS.WWWAddress}, "")
}
