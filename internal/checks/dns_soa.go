package checks

import (
	"context"

	"github.com/kolisko/domain-score/internal/audit"
)

type DNSSOA struct{}

func (DNSSOA) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "dns.soa", Title: "SOA záznam", Category: "dns", Mode: audit.ModeSafe, Weight: 2, Severity: audit.SeverityMedium, Tags: []string{"dns"}}
}

func (c DNSSOA) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if len(ev.DNS.SOA) == 0 {
		return fail(c.Meta(), nil, "Ověřte autoritativní DNS zónu a SOA záznam.", c.Meta().Weight)
	}
	return pass(c.Meta(), map[string]any{"soa": ev.DNS.SOA}, "")
}
