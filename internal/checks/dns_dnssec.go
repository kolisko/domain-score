package checks

import (
	"context"

	"github.com/kolisko/domain-score/internal/audit"
)

type DNSSEC struct{}

func (DNSSEC) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "dns.dnssec_enabled", Title: "DNSSEC je zapnutý", Category: "dns", Mode: audit.ModeSafe, Weight: 4, Severity: audit.SeverityMedium, Tags: []string{"dnssec"}}
}

func (c DNSSEC) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if len(ev.DNS.DNSKEY) == 0 && len(ev.DNS.DS) == 0 {
		return warn(c.Meta(), nil, "Zapněte DNSSEC a publikujte DS záznam u registrátora.", 3)
	}
	return pass(c.Meta(), map[string]any{"dnskey": len(ev.DNS.DNSKEY), "ds": ev.DNS.DS}, "")
}
