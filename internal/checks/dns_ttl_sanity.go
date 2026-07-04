package checks

import (
	"context"

	"github.com/kolisko/domain-score/internal/audit"
)

type DNSTTLSanity struct{}

func (DNSTTLSanity) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "dns.ttl_sanity", Title: "Rozumné TTL hodnoty", Category: "dns", Mode: audit.ModeSafe, Weight: 2, Severity: audit.SeverityLow, Tags: []string{"dns"}}
}

func (c DNSTTLSanity) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if ev.DNS.MinTTL == 0 && ev.DNS.MaxTTL == 0 {
		return warn(c.Meta(), nil, "Nepodařilo se zjistit TTL hodnoty přes DNS dotazy.", 1)
	}
	if ev.DNS.MinTTL < 60 || ev.DNS.MaxTTL > 86400 {
		return warn(c.Meta(), map[string]any{"min_ttl": ev.DNS.MinTTL, "max_ttl": ev.DNS.MaxTTL}, "Udržujte TTL typicky mezi 300 a 86400 sekundami podle provozních potřeb.", 1)
	}
	return pass(c.Meta(), map[string]any{"min_ttl": ev.DNS.MinTTL, "max_ttl": ev.DNS.MaxTTL}, "")
}
