package checks

import (
	"context"

	"github.com/kolisko/domain-score/internal/audit"
)

type AggressiveDeepCrawl struct{}
type AggressiveSubdomainEnumeration struct{}
type AggressivePortScan struct{}
type AggressiveSensitivePaths struct{}
type AggressiveFingerprint struct{}
type AggressiveAXFR struct{}
type AggressiveTokenHints struct{}

func (AggressiveDeepCrawl) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "aggressive.deep_crawl", Title: "Rate-limitovaný hlubší crawl", Category: "aggressive", Mode: audit.ModeAggressive, Weight: 4, Severity: audit.SeverityMedium, Tags: []string{"crawl"}}
}
func (c AggressiveDeepCrawl) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if len(ev.Aggressive.BrokenLinks) > 0 || len(ev.Aggressive.MixedContent) > 0 {
		return warn(c.Meta(), map[string]any{"broken_links": ev.Aggressive.BrokenLinks, "mixed_content": ev.Aggressive.MixedContent}, "Opravte rozbité odkazy a mixed content nalezené při omezeném crawlu.", 3)
	}
	return pass(c.Meta(), map[string]any{"crawled_urls": ev.Aggressive.CrawledURLs}, "")
}

func (AggressiveSubdomainEnumeration) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "aggressive.subdomain_enumeration", Title: "Subdomain enumeration", Category: "aggressive", Mode: audit.ModeAggressive, Weight: 3, Severity: audit.SeverityMedium, Tags: []string{"dns", "inventory"}}
}
func (c AggressiveSubdomainEnumeration) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	return pass(c.Meta(), map[string]any{"subdomains": ev.Aggressive.Subdomains}, "")
}

func (AggressivePortScan) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "aggressive.port_scan", Title: "Omezený port scan", Category: "aggressive", Mode: audit.ModeAggressive, Weight: 5, Severity: audit.SeverityHigh, Tags: []string{"ports"}}
}
func (c AggressivePortScan) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	risky := []int{}
	for _, p := range ev.Aggressive.OpenPorts {
		if p != 80 && p != 443 {
			risky = append(risky, p)
		}
	}
	if len(risky) > 0 {
		return warn(c.Meta(), map[string]any{"open_ports": ev.Aggressive.OpenPorts, "review": risky}, "Zkontrolujte, zda jsou otevřené ne-webové porty záměrně veřejné.", 3)
	}
	return pass(c.Meta(), map[string]any{"open_ports": ev.Aggressive.OpenPorts}, "")
}

func (AggressiveSensitivePaths) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "aggressive.sensitive_paths", Title: "Citlivé veřejné cesty", Category: "aggressive", Mode: audit.ModeAggressive, Weight: 6, Severity: audit.SeverityCritical, Tags: []string{"exposure"}}
}
func (c AggressiveSensitivePaths) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if len(ev.Aggressive.SensitivePaths) > 0 {
		return fail(c.Meta(), map[string]any{"sensitive_paths": ev.Aggressive.SensitivePaths}, "Odstraňte veřejně dostupné citlivé soubory a cesty.", c.Meta().Weight)
	}
	return pass(c.Meta(), nil, "")
}

func (AggressiveFingerprint) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "aggressive.framework_fingerprint", Title: "Framework/CMS fingerprint", Category: "aggressive", Mode: audit.ModeAggressive, Weight: 3, Severity: audit.SeverityMedium, Tags: []string{"fingerprint"}}
}
func (c AggressiveFingerprint) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if len(ev.Aggressive.FrameworkSignals) > 0 {
		return warn(c.Meta(), map[string]any{"signals": ev.Aggressive.FrameworkSignals}, "Omezte veřejné verze frameworků a ověřte známé CVE ručně.", 2)
	}
	return pass(c.Meta(), nil, "")
}

func (AggressiveAXFR) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "aggressive.dns_axfr", Title: "DNS AXFR pokus", Category: "aggressive", Mode: audit.ModeAggressive, Weight: 5, Severity: audit.SeverityHigh, Tags: []string{"dns"}}
}
func (c AggressiveAXFR) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	for ns, status := range ev.Aggressive.AXFR {
		if status == "allowed" {
			return fail(c.Meta(), map[string]any{"nameserver": ns}, "Zakažte veřejný AXFR transfer zóny.", c.Meta().Weight)
		}
	}
	return pass(c.Meta(), map[string]any{"axfr": ev.Aggressive.AXFR}, "")
}

func (AggressiveTokenHints) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "aggressive.exposed_token_hints", Title: "Hinty veřejných tokenů", Category: "aggressive", Mode: audit.ModeAggressive, Weight: 5, Severity: audit.SeverityHigh, Tags: []string{"secrets"}}
}
func (c AggressiveTokenHints) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if len(ev.Aggressive.ExposedTokenHints) > 0 {
		return warn(c.Meta(), map[string]any{"token_hints": ev.Aggressive.ExposedTokenHints}, "Prověřte nalezené token-like hodnoty a přesuňte secrets mimo veřejné assety.", 3)
	}
	return pass(c.Meta(), nil, "")
}
