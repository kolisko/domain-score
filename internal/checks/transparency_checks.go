package checks

import (
	"context"
	"strings"

	"github.com/kolisko/domain-score/internal/audit"
)

type TransparencySecurityTxt struct{}
type TransparencyPolicyPages struct{}
type TransparencyRDAP struct{}
type TransparencyCT struct{}

func (TransparencySecurityTxt) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "transparency.security_txt", Title: "security.txt", Category: "transparency", Mode: audit.ModeSafe, Weight: 3, Severity: audit.SeverityMedium, Tags: []string{"security", "disclosure"}}
}
func (c TransparencySecurityTxt) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if ev.SecurityText.StatusCode != 200 {
		return warn(c.Meta(), map[string]any{"status": ev.SecurityText.StatusCode}, "Publikujte `/.well-known/security.txt` s kontaktem pro zranitelnosti.", 2)
	}
	return pass(c.Meta(), map[string]any{"url": ev.SecurityText.URL}, "")
}

func (TransparencyPolicyPages) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "transparency.policy_pages", Title: "Privacy/terms discovery", Category: "transparency", Mode: audit.ModeSafe, Weight: 2, Severity: audit.SeverityLow, Tags: []string{"privacy", "trust"}}
}
func (c TransparencyPolicyPages) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	body := strings.ToLower(ev.HTTP.Body)
	if strings.Contains(body, "privacy") || strings.Contains(body, "terms") || strings.Contains(body, "gdpr") || strings.Contains(body, "soukrom") {
		return pass(c.Meta(), nil, "")
	}
	return warn(c.Meta(), nil, "Odkazujte z webu na privacy policy a obchodní/používací podmínky, pokud jsou relevantní.", 1)
}

func (TransparencyRDAP) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "transparency.rdap", Title: "RDAP/registrar informace", Category: "transparency", Mode: audit.ModeSafe, Weight: 2, Severity: audit.SeverityInfo, Tags: []string{"domain"}}
}
func (c TransparencyRDAP) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if ev.RDAP.Error != "" || ev.RDAP.Domain == "" {
		return warn(c.Meta(), map[string]any{"error": ev.RDAP.Error}, "RDAP informace nebylo možné ověřit z veřejných zdrojů.", 1)
	}
	return pass(c.Meta(), map[string]any{"domain": ev.RDAP.Domain, "registrar": ev.RDAP.Registrar, "events": ev.RDAP.Events}, "")
}

func (TransparencyCT) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "transparency.certificate_transparency", Title: "Certificate Transparency signály", Category: "transparency", Mode: audit.ModeSafe, Weight: 2, Severity: audit.SeverityInfo, Tags: []string{"tls", "ct"}}
}
func (c TransparencyCT) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if ev.CT.Error != "" {
		return warn(c.Meta(), map[string]any{"error": ev.CT.Error}, "CT zdroj nebyl dostupný; audit lze zopakovat později.", 1)
	}
	if len(ev.CT.KnownNames) == 0 {
		return warn(c.Meta(), nil, "Ve veřejných CT zdrojích nebyly nalezeny další názvy.", 1)
	}
	return pass(c.Meta(), map[string]any{"known_names_count": len(ev.CT.KnownNames)}, "")
}
