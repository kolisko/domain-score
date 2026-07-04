package checks

import (
	"context"
	"strings"

	"github.com/kolisko/domain-score/internal/audit"
)

type DNSSPF struct{}

func (DNSSPF) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "dns.spf", Title: "SPF politika", Category: "dns", Mode: audit.ModeSafe, Weight: 4, Severity: audit.SeverityHigh, Tags: []string{"email", "anti-abuse"}}
}

func (c DNSSPF) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	for _, txt := range ev.DNS.TXT {
		if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
			if strings.Contains(txt, "-all") {
				return pass(c.Meta(), map[string]any{"spf": txt}, "")
			}
			return warn(c.Meta(), map[string]any{"spf": txt}, "Zvažte zakončení SPF politiky pomocí `-all`, pokud je politika kompletní.", 2)
		}
	}
	return fail(c.Meta(), nil, "Přidejte SPF TXT záznam pro omezení spoofingu e-mailů.", c.Meta().Weight)
}
