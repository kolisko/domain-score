package tools

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/kolisko/domain-score/internal/audit"
)

func resultsFromObservation(obs audit.ToolObservation) []audit.Result {
	if !obs.Enabled {
		return nil
	}
	findingsByTool := map[string][]audit.ToolFinding{}
	for _, finding := range obs.Findings {
		findingsByTool[finding.Tool] = append(findingsByTool[finding.Tool], finding)
	}
	selected := selectedToolSet(obs)
	completed := completedToolSet(obs)
	if len(obs.Errors) > 0 && len(obs.RawFiles) == 0 && len(obs.Findings) == 0 {
		return []audit.Result{runtimeResult(obs)}
	}
	results := []audit.Result{}
	if selected["subfinder"] || selected["amass"] {
		ok := completed["subfinder"] || completed["amass"] || len(findingsByTool["subfinder"])+len(findingsByTool["amass"]) > 0
		results = append(results, inventoryResult("tools.subdomain_inventory", "Externí subdoménový inventář", "subfinder/amass subdomény", 3, []audit.ToolFinding{}, append(findingsByTool["subfinder"], findingsByTool["amass"]...), ok))
	}
	if selected["httpx"] {
		results = append(results, inventoryResult("tools.http_probe_inventory", "Externí HTTP probe inventář", "httpx aktivní webové služby", 3, []audit.ToolFinding{}, findingsByTool["httpx"], completed["httpx"]))
	}
	if selected["naabu"] {
		results = append(results, findingsResult("tools.open_ports", "Externě zjištěné otevřené porty", 5, audit.SeverityMedium, findingsByTool["naabu"], "Ověřte, že všechny veřejné porty mají být dostupné a jsou bezpečně nakonfigurované.", completed["naabu"]))
	}
	if selected["nuclei"] {
		results = append(results, findingsResult("tools.nuclei_findings", "Nuclei nálezy", 6, audit.SeverityHigh, findingsByTool["nuclei"], "Ověřte Nuclei nálezy, opravte relevantní misconfigy/CVE a falešné pozitivy zdokumentujte.", completed["nuclei"]))
	}
	if selected["zap"] {
		results = append(results, findingsResult("tools.zap_baseline_alerts", "ZAP Baseline alerty", 4, audit.SeverityMedium, findingsByTool["zap"], "Opravte relevantní ZAP baseline alerty ve webové aplikaci nebo bezpečnostních hlavičkách.", completed["zap"]))
	}
	if selected["testssl"] {
		results = append(results, findingsResult("tools.testssl_findings", "testssl.sh TLS nálezy", 5, audit.SeverityHigh, findingsByTool["testssl"], "Upravte TLS protokoly, ciphery a certifikátovou konfiguraci podle testssl.sh.", completed["testssl"]))
	}
	if selected["internetnl"] {
		results = append(results, findingsResult("tools.internetnl_score", "Internet.nl compliance nálezy", 4, audit.SeverityMedium, findingsByTool["internetnl"], "Opravte moderní internetové standardy podle Internet.nl zjištění.", completed["internetnl"]))
	}
	if selected["greenbone"] {
		results = append(results, findingsResult("tools.greenbone_findings", "Greenbone vulnerability nálezy", 7, audit.SeverityCritical, findingsByTool["greenbone"], "Ověřte Greenbone nálezy, patchujte zranitelné služby a omezte zbytečnou expozici.", completed["greenbone"]))
	}
	if len(obs.Errors) > 0 {
		results = append(results, runtimeResult(obs))
	}
	return results
}

func runtimeResult(obs audit.ToolObservation) audit.Result {
	return audit.Result{
		CheckID:     "tools.runtime",
		Title:       "Docker runtime externích nástrojů",
		Category:    "external_tools",
		Mode:        audit.ModeAggressive,
		Status:      audit.StatusError,
		Severity:    audit.SeverityMedium,
		Weight:      8,
		ScoreImpact: 0,
		Evidence: map[string]any{
			"errors":   obs.Errors,
			"image":    obs.Image,
			"runtime":  obs.Runtime,
			"selected": obs.Selected,
		},
		Recommendation: "Zkontrolujte Docker, dostupnost image a spusťte `domain-score tools doctor`.",
	}
}

func inventoryResult(id string, title string, evidenceLabel string, weight int, expected []audit.ToolFinding, findings []audit.ToolFinding, completed bool) audit.Result {
	if !completed {
		return toolIncompleteResult(id, title, weight, map[string]any{evidenceLabel: findings, "count": len(findings)})
	}
	status := audit.StatusPass
	recommendation := "Inventář byl vytvořen."
	if len(findings) == 0 && len(expected) == 0 {
		status = audit.StatusWarn
		recommendation = "Externí nástroj nevrátil žádná data; ověřte konfiguraci, konektivitu nebo limity zdrojů."
	}
	return audit.Result{
		CheckID:        id,
		Title:          title,
		Category:       "external_tools",
		Mode:           audit.ModeAggressive,
		Status:         status,
		Severity:       audit.SeverityInfo,
		Weight:         weight,
		ScoreImpact:    scoreImpact(status, weight, nil),
		Evidence:       map[string]any{evidenceLabel: findings, "count": len(findings)},
		Recommendation: recommendation,
	}
}

func findingsResult(id string, title string, weight int, severity audit.Severity, findings []audit.ToolFinding, recommendation string, completed bool) audit.Result {
	if !completed {
		return toolIncompleteResult(id, title, weight, map[string]any{"findings": findings, "count": len(findings), "summary": findingSummary(findings)})
	}
	status := audit.StatusPass
	if len(findings) > 0 {
		status = highestStatus(findings)
	}
	return audit.Result{
		CheckID:        id,
		Title:          title,
		Category:       "external_tools",
		Mode:           audit.ModeAggressive,
		Status:         status,
		Severity:       severity,
		Weight:         weight,
		ScoreImpact:    scoreImpact(status, weight, findings),
		Evidence:       map[string]any{"findings": findings, "count": len(findings), "summary": findingSummary(findings)},
		Recommendation: recommendation,
	}
}

func toolIncompleteResult(id string, title string, weight int, evidence map[string]any) audit.Result {
	return audit.Result{
		CheckID:        id,
		Title:          title,
		Category:       "external_tools",
		Mode:           audit.ModeAggressive,
		Status:         audit.StatusError,
		Severity:       audit.SeverityMedium,
		Weight:         weight,
		ScoreImpact:    0,
		Evidence:       evidence,
		Recommendation: "Externí nástroj nebyl dokončen; zkontrolujte raw výstupy, timeout a běh Docker kontejneru.",
	}
}

func selectedToolSet(obs audit.ToolObservation) map[string]bool {
	out := map[string]bool{}
	for _, tool := range obs.Selected {
		out[tool] = true
	}
	if len(out) == 0 {
		for _, finding := range obs.Findings {
			out[finding.Tool] = true
		}
	}
	return out
}

func completedToolSet(obs audit.ToolObservation) map[string]bool {
	out := map[string]bool{}
	for _, raw := range obs.RawFiles {
		base := filepath.Base(raw)
		if strings.HasSuffix(base, ".status") {
			out[strings.TrimSuffix(base, ".status")] = true
		}
	}
	for _, finding := range obs.Findings {
		out[finding.Tool] = true
	}
	return out
}

func highestStatus(findings []audit.ToolFinding) audit.Status {
	status := audit.StatusWarn
	for _, finding := range findings {
		switch normalizeSeverity(finding.Severity) {
		case "critical", "high":
			return audit.StatusFail
		case "medium":
			status = audit.StatusFail
		}
	}
	return status
}

func scoreImpact(status audit.Status, weight int, findings []audit.ToolFinding) int {
	switch status {
	case audit.StatusFail:
		return weight
	case audit.StatusWarn:
		if len(findings) > 5 {
			return max(1, weight/2)
		}
		return max(1, weight/3)
	default:
		return 0
	}
}

func findingSummary(findings []audit.ToolFinding) map[string]int {
	out := map[string]int{}
	for _, finding := range findings {
		key := normalizeSeverity(finding.Severity)
		out[key]++
	}
	return out
}

func DescribeTools(selected []string) string {
	if len(selected) == 0 {
		return "none"
	}
	return fmt.Sprintf("%v", selected)
}
