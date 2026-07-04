package runner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/kolisko/domain-score/internal/audit"
	"github.com/kolisko/domain-score/internal/checks"
	"github.com/kolisko/domain-score/internal/netx"
	"github.com/kolisko/domain-score/internal/score"
	exttools "github.com/kolisko/domain-score/internal/tools"
)

type Options struct {
	Profile     string
	Aggressive  bool
	Enable      []string
	Disable     []string
	Timeout     time.Duration
	UserAgent   string
	WeightsYAML []byte
	Version     string
	Tools       exttools.Options
}

func Run(ctx context.Context, target audit.Target, opts Options) (audit.Report, error) {
	selected, err := Select(checks.Registry(), opts)
	if err != nil {
		return audit.Report{}, err
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
		results = append(results, res)
	}
	toolResult, err := exttools.Run(ctx, target, opts.Tools)
	if err != nil {
		return audit.Report{}, err
	}
	if toolResult.Observation.Enabled {
		ev.Tools = toolResult.Observation
		results = append(results, toolResult.Results...)
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
		if weight, ok := weights[meta.ID]; ok {
			meta.Weight = weight
			check = weightedCheck{Check: check, meta: meta}
		}
		_, explicitlyEnabled := enable[meta.ID]
		if _, disabled := disable[meta.ID]; disabled {
			continue
		}
		if meta.Mode == audit.ModeAggressive && !allowAggressive && !explicitlyEnabled {
			continue
		}
		selected = append(selected, check)
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("no checks selected")
	}
	return selected, nil
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
