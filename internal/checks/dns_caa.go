package checks

import (
	"context"

	"github.com/kolisko/domain-score/internal/audit"
)

type DNSCAA struct{}

func (DNSCAA) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "dns.caa", Title: "CAA politika certifikátů", Category: "dns", Mode: audit.ModeSafe, Weight: 3, Severity: audit.SeverityMedium, Tags: []string{"dns", "tls"}}
}

func (c DNSCAA) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if len(ev.DNS.CAA) == 0 {
		return warn(c.Meta(), nil, "Přidejte CAA záznamy pro omezení autorit, které mohou vydávat certifikáty.", 2)
	}
	return pass(c.Meta(), map[string]any{"caa": ev.DNS.CAA}, "")
}
