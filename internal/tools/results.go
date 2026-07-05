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
	statuses := toolStatusMap(obs)
	completed := completedToolSet(obs, statuses)
	if len(obs.Errors) > 0 && len(obs.RawFiles) == 0 && len(obs.Findings) == 0 {
		return []audit.Result{runtimeResult(obs)}
	}
	results := []audit.Result{}
	if selected["subfinder"] || selected["amass"] {
		ok := completed["subfinder"] || completed["amass"] || len(findingsByTool["subfinder"])+len(findingsByTool["amass"]) > 0
		findings := append(findingsByTool["subfinder"], findingsByTool["amass"]...)
		results = append(results, inventoryToolResult(statuses, "tools.subdomain_inventory", "Externí subdoménový inventář", "subfinder/amass subdomény", 3, findings, ok, "subfinder", "amass"))
	}
	if selected["httpx"] {
		results = append(results, inventoryToolResult(statuses, "tools.http_probe_inventory", "Externí HTTP probe inventář", "httpx aktivní webové služby", 3, findingsByTool["httpx"], completed["httpx"], "httpx"))
	}
	if selected["naabu"] {
		results = append(results, findingToolResult(statuses, "tools.open_ports", "Externě zjištěné otevřené porty", 5, audit.SeverityMedium, findingsByTool["naabu"], "Ověřte, že všechny veřejné porty mají být dostupné a jsou bezpečně nakonfigurované.", completed["naabu"], "naabu"))
	}
	if selected["nuclei"] {
		results = append(results, findingToolResult(statuses, "tools.nuclei_findings", "Nuclei nálezy", 6, audit.SeverityHigh, findingsByTool["nuclei"], "Ověřte Nuclei nálezy, opravte relevantní misconfigy/CVE a falešné pozitivy zdokumentujte.", completed["nuclei"], "nuclei"))
	}
	if selected["zap"] {
		results = append(results, findingToolResult(statuses, "tools.zap_baseline_alerts", "ZAP Baseline alerty", 4, audit.SeverityMedium, findingsByTool["zap"], "Opravte relevantní ZAP baseline alerty ve webové aplikaci nebo bezpečnostních hlavičkách.", completed["zap"], "zap"))
	}
	if selected["testssl"] {
		results = append(results, findingToolResult(statuses, "tools.testssl_findings", "testssl.sh TLS nálezy", 5, audit.SeverityHigh, findingsByTool["testssl"], "Upravte TLS protokoly, ciphery a certifikátovou konfiguraci podle testssl.sh.", completed["testssl"], "testssl"))
	}
	if selected["internetnl"] {
		results = append(results, findingToolResult(statuses, "tools.internetnl_score", "Internet.nl compliance nálezy", 4, audit.SeverityMedium, findingsByTool["internetnl"], "Opravte moderní internetové standardy podle Internet.nl zjištění.", completed["internetnl"], "internetnl"))
	}
	if selected["greenbone"] {
		results = append(results, findingToolResult(statuses, "tools.greenbone_findings", "Greenbone vulnerability nálezy", 7, audit.SeverityCritical, findingsByTool["greenbone"], "Ověřte Greenbone nálezy, patchujte zranitelné služby a omezte zbytečnou expozici.", completed["greenbone"], "greenbone"))
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

func inventoryToolResult(statuses map[string]audit.ToolStatus, id string, title string, evidenceLabel string, weight int, findings []audit.ToolFinding, completed bool, tools ...string) audit.Result {
	if failed, status := firstFailedStatus(statuses, tools...); failed {
		return toolFailedResult(id, title, weight, status, map[string]any{evidenceLabel: findings, "count": len(findings)})
	}
	return inventoryResult(id, title, evidenceLabel, weight, []audit.ToolFinding{}, findings, completed)
}

func findingsResult(id string, title string, weight int, severity audit.Severity, findings []audit.ToolFinding, recommendation string, completed bool) audit.Result {
	if !completed {
		return toolIncompleteResult(id, title, weight, map[string]any{"findings": findings, "count": len(findings), "summary": findingSummary(findings)})
	}
	if onlyToolStatusFindings(findings) {
		return toolStatusOnlyResult(id, title, weight, findings, recommendation)
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

func findingToolResult(statuses map[string]audit.ToolStatus, id string, title string, weight int, severity audit.Severity, findings []audit.ToolFinding, recommendation string, completed bool, tools ...string) audit.Result {
	if failed, status := firstFailedStatus(statuses, tools...); failed {
		return toolFailedResult(id, title, weight, status, map[string]any{"findings": findings, "count": len(findings), "summary": findingSummary(findings)})
	}
	return findingsResult(id, title, weight, severity, findings, recommendation, completed)
}

func toolStatusOnlyResult(id string, title string, weight int, findings []audit.ToolFinding, recommendation string) audit.Result {
	for _, finding := range findings {
		if strings.TrimSpace(finding.Recommendation) != "" {
			recommendation = finding.Recommendation
			break
		}
	}
	return audit.Result{
		CheckID:        id,
		Title:          title,
		Category:       "external_tools",
		Mode:           audit.ModeAggressive,
		Status:         audit.StatusNotApplicable,
		Severity:       audit.SeverityInfo,
		Weight:         weight,
		ScoreImpact:    0,
		Evidence:       map[string]any{"findings": findings, "count": len(findings), "summary": findingSummary(findings)},
		Recommendation: recommendation,
	}
}

func onlyToolStatusFindings(findings []audit.ToolFinding) bool {
	if len(findings) == 0 {
		return false
	}
	for _, finding := range findings {
		if !strings.EqualFold(strings.TrimSpace(finding.Type), "tool_status") {
			return false
		}
	}
	return true
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

func toolFailedResult(id string, title string, weight int, status audit.ToolStatus, evidence map[string]any) audit.Result {
	evidence["tool_status"] = status
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
		Recommendation: fmt.Sprintf("Externí nástroj `%s` skončil s exit code %d; zkontrolujte raw stderr/stdout a konfiguraci tools image.", status.Tool, status.ExitCode),
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

func completedToolSet(obs audit.ToolObservation, statuses map[string]audit.ToolStatus) map[string]bool {
	out := map[string]bool{}
	for tool, status := range statuses {
		if status.ExitCode == 0 && strings.EqualFold(status.Status, "done") {
			out[tool] = true
		}
	}
	for _, raw := range obs.RawFiles {
		base := filepath.Base(raw)
		if strings.HasSuffix(base, ".status") && statuses[strings.TrimSuffix(base, ".status")].Tool == "" {
			out[strings.TrimSuffix(base, ".status")] = true
		}
	}
	for _, finding := range obs.Findings {
		out[finding.Tool] = true
	}
	return out
}

func toolStatusMap(obs audit.ToolObservation) map[string]audit.ToolStatus {
	out := map[string]audit.ToolStatus{}
	for _, status := range obs.Statuses {
		if status.Tool == "" {
			continue
		}
		out[status.Tool] = status
	}
	return out
}

func failedStatus(statuses map[string]audit.ToolStatus, tool string) (bool, audit.ToolStatus) {
	status, ok := statuses[tool]
	if !ok {
		return false, audit.ToolStatus{}
	}
	return status.ExitCode != 0, status
}

func firstFailedStatus(statuses map[string]audit.ToolStatus, tools ...string) (bool, audit.ToolStatus) {
	for _, tool := range tools {
		if failed, status := failedStatus(statuses, tool); failed {
			return true, status
		}
	}
	return false, audit.ToolStatus{}
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
