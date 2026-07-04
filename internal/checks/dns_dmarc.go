package checks

import (
	"context"
	"strings"

	"github.com/kolisko/domain-score/internal/audit"
)

type DNSDMARC struct{}

func (DNSDMARC) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "dns.dmarc", Title: "DMARC politika", Category: "dns", Mode: audit.ModeSafe, Weight: 5, Severity: audit.SeverityHigh, Tags: []string{"email", "anti-abuse"}}
}

func (c DNSDMARC) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if len(ev.DNS.DMARCTXT) == 0 {
		return fail(c.Meta(), nil, "Přidejte DMARC TXT záznam na `_dmarc`.", c.Meta().Weight)
	}
	value := strings.Join(ev.DNS.DMARCTXT, " ")
	if strings.Contains(strings.ToLower(value), "p=reject") || strings.Contains(strings.ToLower(value), "p=quarantine") {
		return pass(c.Meta(), map[string]any{"dmarc": ev.DNS.DMARCTXT}, "")
	}
	return warn(c.Meta(), map[string]any{"dmarc": ev.DNS.DMARCTXT}, "DMARC je přítomný, ale politika není vynucená; přejděte z `p=none` na `quarantine` nebo `reject`.", 3)
}
