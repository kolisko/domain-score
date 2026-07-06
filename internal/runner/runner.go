package runner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/kolisko/domain-score/internal/audit"
	"github.com/kolisko/domain-score/internal/catalog"
	"github.com/kolisko/domain-score/internal/checks"
	"github.com/kolisko/domain-score/internal/netx"
	"github.com/kolisko/domain-score/internal/score"
	exttools "github.com/kolisko/domain-score/internal/tools"
)

type Options struct {
	Profile       string
	Aggressive    bool
	Enable        []string
	Disable       []string
	Timeout       time.Duration
	UserAgent     string
	WeightsYAML   []byte
	Version       string
	Tools         exttools.Options
	CheckID       string
	ReportCheckID string
	ToolChecks    []string
}

func Run(ctx context.Context, target audit.Target, opts Options) (audit.Report, error) {
	selected, err := Select(checks.Registry(), opts)
	if err != nil {
		return audit.Report{}, err
	}
	selectedTools, _ := exttools.ExpandList(opts.Tools.Tools)
	if len(selected) == 0 && len(selectedTools) == 0 {
		if opts.ReportCheckID != "" {
			results := []audit.Result{unsupportedCatalogResult(opts.ReportCheckID)}
			return audit.Report{
				Target:      target,
				GeneratedAt: time.Now().UTC(),
				Profile:     normalizedProfile(opts),
				Aggressive:  false,
				Score:       score.Calculate(results),
				Results:     results,
				Evidence:    audit.SharedEvidence{},
				Version:     opts.Version,
			}, nil
		}
		return audit.Report{}, fmt.Errorf("no checks selected")
	}
	ev := audit.SharedEvidence{}
	if len(selected) > 0 {
		ev = netx.Collect(ctx, target, netx.Options{
			Aggressive: includesAggressive(selected),
			Timeout:    opts.Timeout,
			UserAgent:  opts.UserAgent,
		})
	}
	results := make([]audit.Result, 0, len(selected))
	for _, check := range selected {
		meta := check.Meta()
		timeout := meta.Timeout
		if timeout == 0 {
			timeout = 5 * time.Second
		}
		cctx, cancel := context.WithTimeout(ctx, timeout)
		start := time.Now()
		res := check.Run(cctx, target, ev)
		cancel()
		res.Duration = time.Since(start).String()
		if res.CheckID == "" {
			res.CheckID = meta.ID
			res.Title = meta.Title
			res.Category = meta.Category
			res.Mode = meta.Mode
			res.Weight = meta.Weight
			res.Severity = meta.Severity
		}
		if opts.ReportCheckID != "" && opts.ReportCheckID != opts.CheckID && res.CheckID == opts.CheckID {
			res = rewriteResultToCatalogCheck(res, opts.ReportCheckID, opts.CheckID)
		}
		results = append(results, res)
	}
	toolResult, err := exttools.Run(ctx, target, opts.Tools)
	if err != nil {
		return audit.Report{}, err
	}
	if toolResult.Observation.Enabled {
		ev.Tools = toolResult.Observation
		if opts.ReportCheckID != "" {
			results = append(results, atomicToolResult(toolResult.Observation, opts.ReportCheckID))
		} else if len(opts.ToolChecks) > 0 {
			results = append(results, atomicToolResultsForTools(toolResult.Observation, opts.ToolChecks)...)
		} else {
			atomicResults := atomicToolResultsForFindings(toolResult.Observation)
			if len(atomicResults) > 0 {
				results = append(results, atomicResults...)
			} else {
				results = append(results, toolResult.Results...)
			}
		}
	}
	aggressive := includesAggressive(selected) || toolResult.Observation.Enabled
	return audit.Report{
		Target:      target,
		GeneratedAt: time.Now().UTC(),
		Profile:     normalizedProfile(opts),
		Aggressive:  aggressive,
		Score:       score.Calculate(results),
		Results:     results,
		Evidence:    ev,
		Version:     opts.Version,
	}, nil
}

func Select(all []audit.Check, opts Options) ([]audit.Check, error) {
	weights, err := parseWeights(opts.WeightsYAML)
	if err != nil {
		return nil, err
	}
	if opts.CheckID == "" && (opts.ReportCheckID != "" || len(opts.ToolChecks) > 0) {
		return []audit.Check{}, nil
	}
	enable := set(opts.Enable)
	disable := set(opts.Disable)
	allowAggressive := opts.Aggressive || strings.EqualFold(opts.Profile, "aggressive")
	selected := []audit.Check{}
	for _, check := range all {
		meta := check.Meta()
		if opts.CheckID != "" && meta.ID != opts.CheckID {
			continue
		}
		if weight, ok := weights[meta.ID]; ok {
			meta.Weight = weight
			check = weightedCheck{Check: check, meta: meta}
		}
		_, explicitlyEnabled := enable[meta.ID]
		if _, disabled := disable[meta.ID]; disabled {
			continue
		}
		if opts.CheckID == "" && meta.Mode == audit.ModeAggressive && !allowAggressive && !explicitlyEnabled {
			continue
		}
		selected = append(selected, check)
	}
	if opts.CheckID != "" {
		return selected, nil
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("no checks selected")
	}
	return selected, nil
}

func rewriteResultToCatalogCheck(res audit.Result, checkID string, runtimeCheckID string) audit.Result {
	cat, err := catalog.LoadEmbedded()
	if err != nil {
		return res
	}
	check, ok := cat.FindCheck(checkID)
	if !ok {
		return res
	}
	res.CheckID = check.ID
	res.Title = check.Title
	res.Category = check.Category
	res.Mode = audit.Mode(check.Mode)
	res.Severity = audit.Severity(check.Severity)
	res.Weight = check.Weight
	if res.Recommendation == "" {
		res.Recommendation = check.Remediation
	}
	if res.Evidence == nil {
		res.Evidence = map[string]any{}
	}
	res.Evidence["runtime_check_id"] = runtimeCheckID
	return res
}

func atomicToolResult(obs audit.ToolObservation, checkID string) audit.Result {
	cat, err := catalog.LoadEmbedded()
	if err != nil {
		return audit.Result{
			CheckID:  checkID,
			Title:    checkID,
			Category: "external_tools",
			Status:   audit.StatusError,
			Severity: audit.SeverityMedium,
			Error:    err.Error(),
		}
	}
	check, ok := cat.FindCheck(checkID)
	if !ok {
		return audit.Result{
			CheckID:  checkID,
			Title:    checkID,
			Category: "external_tools",
			Status:   audit.StatusError,
			Severity: audit.SeverityMedium,
			Error:    "unknown catalog check",
		}
	}
	findings := []audit.ToolFinding{}
	for _, finding := range obs.Findings {
		if finding.AtomicCheckID == checkID {
			findings = append(findings, finding)
		}
	}
	return atomicCatalogToolResult(obs, check, findings)
}

func unsupportedCatalogResult(checkID string) audit.Result {
	cat, err := catalog.LoadEmbedded()
	if err != nil {
		return audit.Result{
			CheckID:        checkID,
			Title:          checkID,
			Category:       "catalog",
			Status:         audit.StatusError,
			Severity:       audit.SeverityMedium,
			Recommendation: "Catalog could not be loaded.",
			Error:          err.Error(),
		}
	}
	check, ok := cat.FindCheck(checkID)
	if !ok {
		return audit.Result{
			CheckID:        checkID,
			Title:          checkID,
			Category:       "catalog",
			Status:         audit.StatusError,
			Severity:       audit.SeverityMedium,
			Recommendation: "Unknown catalog check.",
		}
	}
	return audit.Result{
		CheckID:        check.ID,
		Title:          check.Title,
		Category:       check.Category,
		Mode:           audit.Mode(check.Mode),
		Status:         audit.StatusNotApplicable,
		Severity:       audit.Severity(check.Severity),
		Weight:         check.Weight,
		ScoreImpact:    0,
		Evidence:       map[string]any{"coverage_status": check.CoverageStatus, "sources": check.SourceLabels(), "reason": "check is cataloged but has no runnable internal check or supported local tool runtime"},
		Recommendation: "Tento atomic check je v katalogu, ale aktuální release ho neumí samostatně spustit bez další integrace zdroje.",
	}
}

func atomicToolResultsForFindings(obs audit.ToolObservation) []audit.Result {
	ids := []string{}
	seen := map[string]bool{}
	for _, finding := range obs.Findings {
		if finding.AtomicCheckID == "" || seen[finding.AtomicCheckID] {
			continue
		}
		seen[finding.AtomicCheckID] = true
		ids = append(ids, finding.AtomicCheckID)
	}
	results := make([]audit.Result, 0, len(ids))
	for _, id := range ids {
		results = append(results, atomicToolResult(obs, id))
	}
	return results
}

func atomicToolResultsForTools(obs audit.ToolObservation, tools []string) []audit.Result {
	cat, err := catalog.LoadEmbedded()
	if err != nil {
		return []audit.Result{{
			CheckID:  "tools.catalog",
			Title:    "Tool check catalog",
			Category: "external_tools",
			Status:   audit.StatusError,
			Severity: audit.SeverityMedium,
			Error:    err.Error(),
		}}
	}
	checks := cat.ChecksForTools(tools)
	results := make([]audit.Result, 0, len(checks))
	for _, check := range checks {
		findings := []audit.ToolFinding{}
		for _, finding := range obs.Findings {
			if finding.AtomicCheckID == check.ID {
				findings = append(findings, finding)
			}
		}
		results = append(results, atomicCatalogToolResult(obs, check, findings))
	}
	return results
}

func atomicCatalogToolResult(obs audit.ToolObservation, check catalog.Check, findings []audit.ToolFinding) audit.Result {
	status := audit.StatusPass
	recommendation := check.Remediation
	reason := ""
	if len(obs.Errors) > 0 && len(obs.RawFiles) == 0 && len(findings) == 0 {
		status = audit.StatusError
		reason = "tool runtime produced errors and no raw evidence"
	} else if len(findings) > 0 {
		if onlyStatusFindings(findings) {
			status = audit.StatusNotApplicable
			reason = "tool returned status metadata, not audit evidence for this atomic check"
		} else {
			status = highestFindingStatus(findings)
			reason = "mapped tool finding exists"
		}
	} else if !toolEvidenceAvailable(obs, check) {
		status = audit.StatusError
		reason = "selected tool did not produce operational audit evidence for this atomic check"
		recommendation = "Zkontrolujte raw výstupy a integraci daného nástroje; check nelze hodnotit bez skutečné evidence."
	} else if !canPassWithoutFinding(check) {
		status = audit.StatusNotApplicable
		reason = "check is cataloged, but negative evidence is not implemented strongly enough to prove a PASS"
		recommendation = "Tento atomic check je v katalogu, ale zatím nemá plnou runtime normalizaci pro průkazný negativní výsledek."
	} else if strings.HasPrefix(check.ID, "inventory.") {
		status = audit.StatusWarn
		reason = "inventory-capable tool completed but returned no inventory records"
	} else {
		reason = "implemented source completed and returned no mapped findings"
	}
	return audit.Result{
		CheckID:        check.ID,
		Title:          check.Title,
		Category:       check.Category,
		Mode:           audit.Mode(check.Mode),
		Status:         status,
		Severity:       audit.Severity(check.Severity),
		Weight:         check.Weight,
		ScoreImpact:    atomicScoreImpact(status, check.Weight, findings),
		Evidence:       map[string]any{"findings": findings, "count": len(findings), "tools": obs.Selected, "sources": selectedToolSourceLabels(obs.Selected, check), "errors": obs.Errors, "coverage_status": check.CoverageStatus, "reason": reason},
		Recommendation: recommendation,
	}
}

func onlyStatusFindings(findings []audit.ToolFinding) bool {
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

func canPassWithoutFinding(check catalog.Check) bool {
	switch strings.TrimSpace(check.CoverageStatus) {
	case "implemented":
		return true
	case "partial":
		return true
	default:
		return false
	}
}

func toolEvidenceAvailable(obs audit.ToolObservation, check catalog.Check) bool {
	statuses := map[string]audit.ToolStatus{}
	for _, status := range obs.Statuses {
		if strings.TrimSpace(status.Tool) != "" {
			statuses[status.Tool] = status
		}
	}
	selected := set(obs.Selected)
	for _, tool := range check.ToolNames() {
		if len(selected) > 0 && !selected[tool] {
			continue
		}
		if !toolCompleted(statuses[tool]) {
			continue
		}
		if toolRequiresPositiveOperationalFinding(tool) {
			if hasNonStatusFindingForTool(obs.Findings, tool) {
				return true
			}
			continue
		}
		if hasRawFileForTool(obs.RawFiles, tool) {
			return true
		}
		if hasNonStatusFindingForTool(obs.Findings, tool) {
			return true
		}
	}
	return false
}

func toolCompleted(status audit.ToolStatus) bool {
	return status.Tool != "" && status.ExitCode == 0 && strings.EqualFold(strings.TrimSpace(status.Status), "done")
}

func toolRequiresPositiveOperationalFinding(tool string) bool {
	switch tool {
	case "internetnl", "greenbone":
		return true
	default:
		return false
	}
}

func hasNonStatusFindingForTool(findings []audit.ToolFinding, tool string) bool {
	for _, finding := range findings {
		if finding.Tool == tool && !strings.EqualFold(strings.TrimSpace(finding.Type), "tool_status") {
			return true
		}
	}
	return false
}

func hasRawFileForTool(rawFiles []string, tool string) bool {
	for _, raw := range rawFiles {
		base := strings.TrimSpace(raw)
		if strings.Contains(base, "/"+tool+".") || strings.HasPrefix(base, tool+".") || strings.Contains(base, "\\"+tool+".") {
			return true
		}
	}
	return false
}

func selectedToolSourceLabels(selected []string, check catalog.Check) []string {
	want := map[string]bool{}
	for _, tool := range selected {
		tool = strings.TrimSpace(tool)
		if tool != "" {
			want[tool] = true
		}
	}
	labels := []string{}
	for _, tool := range check.ToolNames() {
		if want[tool] {
			labels = append(labels, "tool:"+tool)
		}
	}
	if len(labels) > 0 {
		return labels
	}
	return check.SourceLabels()
}

func highestFindingStatus(findings []audit.ToolFinding) audit.Status {
	status := audit.StatusWarn
	for _, finding := range findings {
		switch strings.ToLower(strings.TrimSpace(finding.Severity)) {
		case "critical", "high":
			return audit.StatusFail
		case "medium":
			status = audit.StatusFail
		}
	}
	return status
}

func atomicScoreImpact(status audit.Status, weight int, findings []audit.ToolFinding) int {
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

func normalizedProfile(opts Options) string {
	if opts.Profile == "" {
		return "safe"
	}
	return opts.Profile
}

func includesAggressive(checks []audit.Check) bool {
	for _, check := range checks {
		if check.Meta().Mode == audit.ModeAggressive {
			return true
		}
	}
	return false
}

func set(vals []string) map[string]bool {
	out := map[string]bool{}
	for _, v := range vals {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out[part] = true
			}
		}
	}
	return out
}

func parseWeights(raw []byte) (map[string]int, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var cfg struct {
		Weights map[string]int `yaml:"weights"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	return cfg.Weights, nil
}

type weightedCheck struct {
	audit.Check
	meta audit.CheckMeta
}

func (w weightedCheck) Meta() audit.CheckMeta {
	return w.meta
}
