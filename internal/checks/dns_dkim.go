package checks

import (
	"context"

	"github.com/kolisko/domain-score/internal/audit"
)

type DNSDKIM struct{}

func (DNSDKIM) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "dns.dkim", Title: "DKIM podpisování e-mailů", Category: "dns", Mode: audit.ModeSafe, Weight: 4, Severity: audit.SeverityHigh, Tags: []string{"email", "anti-abuse"}}
}

func (c DNSDKIM) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if len(ev.DNS.DKIMFound) == 0 {
		return warn(c.Meta(), nil, "Nebyl nalezen DKIM záznam pro běžné selectory; pokud doména posílá e-mail, publikujte DKIM a/nebo rozšiřte selector discovery.", 3)
	}
	return pass(c.Meta(), map[string]any{"selectors": ev.DNS.DKIMFound}, "")
}
