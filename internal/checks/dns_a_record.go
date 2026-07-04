package checks

import (
	"context"

	"github.com/kolisko/domain-score/internal/audit"
)

type DNSARecord struct{}

func (DNSARecord) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "dns.a_record", Title: "A záznam existuje", Category: "dns", Mode: audit.ModeSafe, Weight: 5, Severity: audit.SeverityHigh, Tags: []string{"dns", "availability"}}
}

func (c DNSARecord) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if len(ev.DNS.A) == 0 {
		return fail(c.Meta(), nil, "Doplňte alespoň jeden A záznam pro apex domény.", c.Meta().Weight)
	}
	return pass(c.Meta(), map[string]any{"a": ev.DNS.A}, "")
}
