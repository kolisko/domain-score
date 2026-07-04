package checks

import (
	"context"

	"github.com/kolisko/domain-score/internal/audit"
)

type ExternalMozillaObservatory struct{}
type ExternalSSLLabs struct{}
type ExternalShodanInternetDBServices struct{}
type ExternalShodanInternetDBCVE struct{}

func (ExternalMozillaObservatory) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "external.mozilla_observatory", Title: "Mozilla Observatory grade", Category: "external_public", Mode: audit.ModeSafe, Weight: 3, Severity: audit.SeverityMedium, Tags: []string{"headers", "observatory"}}
}

func (c ExternalMozillaObservatory) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	g := ev.External.MozillaObservatory
	if g.Error != "" {
		return warn(c.Meta(), map[string]any{"error": g.Error, "url": g.URL}, "Mozilla Observatory public API nebylo možné ověřit; audit zopakujte později.", 1)
	}
	if g.Grade == "" {
		return warn(c.Meta(), map[string]any{"status": g.Status, "url": g.URL}, "Mozilla Observatory nevrátil grade z cache/API odpovědi.", 1)
	}
	if g.Grade == "A+" || g.Grade == "A" || g.Grade == "B" {
		return pass(c.Meta(), map[string]any{"grade": g.Grade, "score": g.Score}, "")
	}
	return warn(c.Meta(), map[string]any{"grade": g.Grade, "score": g.Score}, "Zlepšete security headers podle Mozilla Observatory doporučení.", 2)
}

func (ExternalSSLLabs) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "external.ssl_labs", Title: "SSL Labs grade z veřejné cache", Category: "external_public", Mode: audit.ModeSafe, Weight: 4, Severity: audit.SeverityHigh, Tags: []string{"tls", "ssl-labs"}}
}

func (c ExternalSSLLabs) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	g := ev.External.SSLLabs
	if g.Error != "" {
		return warn(c.Meta(), map[string]any{"error": g.Error, "url": g.URL}, "SSL Labs public API nebylo možné ověřit.", 1)
	}
	if g.Grade == "" {
		return warn(c.Meta(), map[string]any{"status": g.Status, "url": g.URL}, "SSL Labs cache neobsahuje hotový výsledek; spusťte SSL Labs scan nebo audit zopakujte později.", 1)
	}
	if g.Grade == "A+" || g.Grade == "A" || g.Grade == "B" {
		return pass(c.Meta(), map[string]any{"grade": g.Grade, "status": g.Status}, "")
	}
	return warn(c.Meta(), map[string]any{"grade": g.Grade, "status": g.Status}, "Zlepšete TLS konfiguraci podle SSL Labs výsledku.", 3)
}

func (ExternalShodanInternetDBServices) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "external.internetdb_services", Title: "Shodan InternetDB vystavené služby", Category: "external_public", Mode: audit.ModeSafe, Weight: 4, Severity: audit.SeverityHigh, Tags: []string{"shodan", "exposed-services"}}
}

func (c ExternalShodanInternetDBServices) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	s := ev.External.Shodan
	if s.Error != "" && len(s.Ports) == 0 {
		return warn(c.Meta(), map[string]any{"error": s.Error}, "Shodan InternetDB no-key endpoint nebylo možné ověřit.", 1)
	}
	risky := []int{}
	for _, port := range s.Ports {
		if port != 80 && port != 443 {
			risky = append(risky, port)
		}
	}
	if len(risky) > 0 {
		return warn(c.Meta(), map[string]any{"ports": s.Ports, "review": risky, "hostnames": s.Hostnames}, "Ve veřejných Shodan InternetDB datech jsou vidět ne-webové služby; ověřte, že mají být veřejné.", 3)
	}
	return pass(c.Meta(), map[string]any{"ports": s.Ports}, "")
}

func (ExternalShodanInternetDBCVE) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "external.internetdb_cves", Title: "Shodan InternetDB CVE detekce", Category: "external_public", Mode: audit.ModeSafe, Weight: 5, Severity: audit.SeverityCritical, Tags: []string{"shodan", "cve"}}
}

func (c ExternalShodanInternetDBCVE) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	cves := ev.External.Shodan.CVEs
	if len(cves) > 0 {
		return fail(c.Meta(), map[string]any{"cves": cves}, "Shodan InternetDB eviduje CVE na veřejné infrastruktuře; ověřte reálnou zranitelnost a patch/backport stav.", c.Meta().Weight)
	}
	return pass(c.Meta(), nil, "")
}
