package checks

import (
	"context"

	"github.com/kolisko/domain-score/internal/audit"
)

type DNSMTASTS struct{}

func (DNSMTASTS) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "dns.mta_sts", Title: "MTA-STS TXT záznam", Category: "dns", Mode: audit.ModeSafe, Weight: 2, Severity: audit.SeverityLow, Tags: []string{"email", "tls"}}
}

func (c DNSMTASTS) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if len(ev.DNS.MTASTSTXT) == 0 {
		return warn(c.Meta(), nil, "Zvažte MTA-STS pro vynucení TLS při doručování e-mailů.", 1)
	}
	return pass(c.Meta(), map[string]any{"mta_sts": ev.DNS.MTASTSTXT}, "")
}
