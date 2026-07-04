package checks

import (
	"context"

	"github.com/kolisko/domain-score/internal/audit"
)

type DNSMX struct{}

func (DNSMX) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "dns.mx", Title: "MX záznamy", Category: "dns", Mode: audit.ModeSafe, Weight: 2, Severity: audit.SeverityLow, Tags: []string{"dns", "email"}}
}

func (c DNSMX) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if len(ev.DNS.MX) == 0 {
		return warn(c.Meta(), nil, "Pokud doména odesílá nebo přijímá e-mail, nastavte MX záznamy.", 1)
	}
	return pass(c.Meta(), map[string]any{"mx": ev.DNS.MX}, "")
}
