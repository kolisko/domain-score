package checks

import (
	"context"

	"github.com/kolisko/domain-score/internal/audit"
)

type DNSTXT struct{}

func (DNSTXT) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "dns.txt", Title: "TXT záznamy", Category: "dns", Mode: audit.ModeSafe, Weight: 1, Severity: audit.SeverityInfo, Tags: []string{"dns"}}
}

func (c DNSTXT) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if len(ev.DNS.TXT) == 0 {
		return warn(c.Meta(), nil, "TXT záznamy často nesou SPF, ověřovací a bezpečnostní politiku.", 1)
	}
	return pass(c.Meta(), map[string]any{"txt_count": len(ev.DNS.TXT)}, "")
}
