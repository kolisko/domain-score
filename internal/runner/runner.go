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
}

func Run(ctx context.Context, target audit.Target, opts Options) (audit.Report, error) {
	selected, err := Select(checks.Registry(), opts)
	if err != nil {
		return audit.Report{}, err
	}
	selectedTools, _ := exttools.ExpandList(opts.Tools.Tools)
	if len(selected) == 0 && len(selectedTools) == 0 {
		return audit.Report{}, fmt.Errorf("no checks selected")
	}
	ev := netx.Collect(ctx, target, netx.Options{
		Aggressive: includesAggressive(selected),
		Timeout:    opts.Timeout,
		UserAgent:  opts.UserAgent,
	})
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
		} else {
			results = append(results, toolResult.Results...)
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
	status := audit.StatusPass
	if len(obs.Errors) > 0 && len(obs.RawFiles) == 0 && len(findings) == 0 {
		status = audit.StatusError
	} else if len(findings) > 0 {
		status = highestFindingStatus(findings)
	} else if strings.HasPrefix(checkID, "inventory.") {
		status = audit.StatusWarn
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
		Evidence:       map[string]any{"findings": findings, "count": len(findings), "tools": obs.Selected, "errors": obs.Errors},
		Recommendation: check.Remediation,
	}
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
