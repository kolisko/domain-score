package checks

import (
	"context"

	"github.com/kolisko/domain-score/internal/audit"
)

type M365TenantDiscovery struct{}
type M365LegacyAuthProbe struct{}

func (M365TenantDiscovery) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "m365.tenant_discovery", Title: "Microsoft 365 tenant discovery", Category: "microsoft_365", Mode: audit.ModeSafe, Weight: 3, Severity: audit.SeverityMedium, Tags: []string{"m365", "cloud", "email"}}
}

func (c M365TenantDiscovery) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if !ev.M365.Detected {
		return notApplicable(c.Meta(), map[string]any{"openid_status": ev.M365.OpenIDStatusCode}, "Microsoft 365 tenant signály nebyly z veřejných zdrojů detekovány.")
	}
	return pass(c.Meta(), map[string]any{
		"mx":            ev.M365.MXSignals,
		"txt":           ev.M365.TXTSignals,
		"autodiscover":  ev.M365.Autodiscover,
		"openid_issuer": ev.M365.OpenIDIssuer,
		"openid_status": ev.M365.OpenIDStatusCode,
	}, "")
}

func (M365LegacyAuthProbe) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "m365.legacy_auth_probe", Title: "Microsoft 365 legacy auth probe", Category: "microsoft_365", Mode: audit.ModeSafe, Weight: 3, Severity: audit.SeverityHigh, Tags: []string{"m365", "legacy-auth"}}
}

func (c M365LegacyAuthProbe) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if !ev.M365.Detected {
		return notApplicable(c.Meta(), nil, "Microsoft 365 nebyl detekován.")
	}
	return warn(c.Meta(), map[string]any{"probe": ev.M365.LegacyAuthProbe}, "Legacy auth nelze lokálně ověřit bez autorizovaného tenant kontextu; ověřte v Entra ID sign-in logs a Conditional Access, že Basic/legacy auth je blokovaný.", 2)
}
