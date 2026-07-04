package checks

import (
	"context"

	"github.com/kolisko/domain-score/internal/audit"
)

type DNSBIMI struct{}

func (DNSBIMI) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "dns.bimi", Title: "BIMI záznam", Category: "dns", Mode: audit.ModeSafe, Weight: 1, Severity: audit.SeverityInfo, Tags: []string{"email", "brand"}}
}

func (c DNSBIMI) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if len(ev.DNS.BIMITXT) == 0 {
		return warn(c.Meta(), nil, "BIMI je volitelné, ale může zlepšit důvěryhodnost značky v podporovaných mailboxech.", 1)
	}
	return pass(c.Meta(), map[string]any{"bimi": ev.DNS.BIMITXT}, "")
}
