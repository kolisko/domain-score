package checks

import (
	"context"

	"github.com/kolisko/domain-score/internal/audit"
)

type DNSTLSRPT struct{}

func (DNSTLSRPT) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "dns.tls_rpt", Title: "TLS-RPT reporting", Category: "dns", Mode: audit.ModeSafe, Weight: 1, Severity: audit.SeverityLow, Tags: []string{"email", "tls"}}
}

func (c DNSTLSRPT) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if len(ev.DNS.TLSRPTTXT) == 0 {
		return warn(c.Meta(), nil, "Přidejte TLS-RPT záznam pro reporty chyb TLS doručování.", 1)
	}
	return pass(c.Meta(), map[string]any{"tls_rpt": ev.DNS.TLSRPTTXT}, "")
}
