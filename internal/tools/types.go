package tools

import (
	"fmt"
	"strings"
	"time"
)

const (
	RuntimeDocker = "docker"
	RuntimeCache  = "cache"

	DefaultImageRef = "ghcr.io/kolisko/domain-score-tools@sha256:6a816666709aa1e687e040a755bb8efa152c1ef04f5934970ca08a01f185d5de"
	DefaultImageTag = "tools-v0.1.4"

	PullAuto   = "auto"
	PullAlways = "always"
	PullNever  = "never"

	DefaultTimeout = 60 * time.Minute
)

var KnownTools = []string{
	"subfinder",
	"httpx",
	"naabu",
	"nuclei",
	"amass",
	"testssl",
	"zap",
	"internetnl",
	"greenbone",
}

var aliases = map[string][]string{
	"all":              KnownTools,
	"projectdiscovery": {"subfinder", "httpx", "naabu", "nuclei"},
	"web-passive":      {"httpx", "zap"},
	"tls":              {"testssl"},
	"standards":        {"internetnl"},
	"vuln":             {"nuclei", "greenbone"},
}

type Options struct {
	Tools    string
	Runtime  string
	Image    string
	Pull     string
	Timeout  time.Duration
	CacheDir string
	Version  string
}

func DefaultImage(version string) string {
	return DefaultImageRef
}

func NormalizeRuntime(runtime string) (string, error) {
	runtime = strings.ToLower(strings.TrimSpace(runtime))
	if runtime == "" {
		return RuntimeDocker, nil
	}
	switch runtime {
	case RuntimeDocker, RuntimeCache:
		return runtime, nil
	default:
		return "", fmt.Errorf("unsupported tool runtime %q; use docker or cache", runtime)
	}
}

func NormalizePullPolicy(policy string) (string, error) {
	policy = strings.ToLower(strings.TrimSpace(policy))
	if policy == "" {
		return PullAuto, nil
	}
	switch policy {
	case PullAuto, PullAlways, PullNever:
		return policy, nil
	default:
		return "", fmt.Errorf("unsupported tools-pull %q; use auto, always, or never", policy)
	}
}

func ExpandList(raw string) ([]string, error) {
	parts := splitList(raw)
	if len(parts) == 0 || (len(parts) == 1 && parts[0] == "none") {
		return nil, nil
	}
	seen := map[string]bool{}
	out := []string{}
	for _, part := range parts {
		expanded, ok := aliases[part]
		if !ok {
			if !IsKnownTool(part) {
				return nil, fmt.Errorf("unknown tool %q", part)
			}
			expanded = []string{part}
		}
		for _, tool := range expanded {
			if !seen[tool] {
				seen[tool] = true
				out = append(out, tool)
			}
		}
	}
	return out, nil
}

func splitList(raw string) []string {
	out := []string{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func IsKnownTool(tool string) bool {
	for _, known := range KnownTools {
		if tool == known {
			return true
		}
	}
	return false
}
