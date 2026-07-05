package tools

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kolisko/domain-score/internal/audit"
	"github.com/kolisko/domain-score/internal/catalog"
)

func ParseCache(cacheDir string) ([]audit.ToolFinding, []string) {
	rawDir := filepath.Join(cacheDir, "raw")
	findings := []audit.ToolFinding{}
	errors := []string{}
	parsers := []struct {
		file string
		fn   func(string) ([]audit.ToolFinding, error)
	}{
		{"subfinder.jsonl", parseSubfinder},
		{"httpx.jsonl", parseHTTPX},
		{"naabu.jsonl", parseNaabu},
		{"nuclei.jsonl", parseNuclei},
		{"amass.jsonl", parseAmass},
		{"amass.txt", parseAmassText},
		{"zap.json", parseZAP},
		{"testssl.json", parseTestSSL},
		{"internetnl.json", parseSimpleToolJSON("internetnl")},
		{"greenbone.json", parseSimpleToolJSON("greenbone")},
	}
	for _, parser := range parsers {
		path := filepath.Join(rawDir, parser.file)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		got, err := parser.fn(path)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", parser.file, err))
			continue
		}
		findings = append(findings, got...)
	}
	normalizeWithCatalog(findings)
	return findings, errors
}

func ParseStatuses(cacheDir string) ([]audit.ToolStatus, []string) {
	rawDir := filepath.Join(cacheDir, "raw")
	matches, err := filepath.Glob(filepath.Join(rawDir, "*.status"))
	if err != nil {
		return nil, []string{err.Error()}
	}
	statuses := []audit.ToolStatus{}
	errors := []string{}
	for _, path := range matches {
		var status audit.ToolStatus
		if err := readJSON(path, &status); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", filepath.Base(path), err))
			continue
		}
		if status.Tool == "" {
			status.Tool = strings.TrimSuffix(filepath.Base(path), ".status")
		}
		statuses = append(statuses, status)
	}
	return statuses, errors
}

func parseSubfinder(path string) ([]audit.ToolFinding, error) {
	return parseJSONLines(path, func(raw map[string]any) (audit.ToolFinding, bool) {
		host := stringValue(raw, "host")
		if host == "" {
			host = stringValue(raw, "input")
		}
		if host == "" {
			return audit.ToolFinding{}, false
		}
		return audit.ToolFinding{
			Source:        "external_tool",
			Tool:          "subfinder",
			Asset:         host,
			Type:          "subdomain",
			AtomicCheckID: "inventory.subdomains",
			SourceRuleID:  "projectdiscovery.subfinder.passive-subdomain-discovery",
			Severity:      "info",
			Title:         "Discovered subdomain",
			Evidence:      raw,
			RawFile:       path,
		}, true
	})
}

func parseHTTPX(path string) ([]audit.ToolFinding, error) {
	return parseJSONLines(path, func(raw map[string]any) (audit.ToolFinding, bool) {
		url := stringValue(raw, "url")
		if url == "" {
			url = stringValue(raw, "input")
		}
		if url == "" {
			return audit.ToolFinding{}, false
		}
		title := "HTTP service detected"
		if status := intValue(raw, "status_code"); status > 0 {
			title = fmt.Sprintf("HTTP service detected (%d)", status)
		}
		return audit.ToolFinding{
			Source:        "external_tool",
			Tool:          "httpx",
			Asset:         url,
			Type:          "http_service",
			AtomicCheckID: "inventory.http_services",
			SourceRuleID:  "projectdiscovery.httpx.http-service-probing",
			Severity:      "info",
			Title:         title,
			Evidence:      raw,
			RawFile:       path,
		}, true
	})
}

func parseNaabu(path string) ([]audit.ToolFinding, error) {
	return parseJSONLines(path, func(raw map[string]any) (audit.ToolFinding, bool) {
		host := stringValue(raw, "host")
		port := intValue(raw, "port")
		if host == "" || port == 0 {
			return audit.ToolFinding{}, false
		}
		severity := "low"
		if port != 80 && port != 443 {
			severity = "medium"
		}
		return audit.ToolFinding{
			Source:         "external_tool",
			Tool:           "naabu",
			Asset:          fmt.Sprintf("%s:%d", host, port),
			Type:           "open_port",
			AtomicCheckID:  "network.open_ports",
			SourceRuleID:   "projectdiscovery.naabu.port-scan",
			Severity:       severity,
			Title:          fmt.Sprintf("Open port %d", port),
			Evidence:       raw,
			Recommendation: "Ověřte, že otevřený port má být veřejně dostupný, je patchovaný a chráněný odpovídající konfigurací.",
			RawFile:        path,
		}, true
	})
}

func parseNuclei(path string) ([]audit.ToolFinding, error) {
	return parseJSONLines(path, func(raw map[string]any) (audit.ToolFinding, bool) {
		info, _ := raw["info"].(map[string]any)
		title := stringValue(info, "name")
		if title == "" {
			title = stringValue(raw, "template-id")
		}
		if title == "" {
			title = "Nuclei finding"
		}
		severity := strings.ToLower(stringValue(info, "severity"))
		if severity == "" {
			severity = "info"
		}
		templateID := stringValue(raw, "template-id")
		sourceRuleID := ""
		if templateID != "" {
			sourceRuleID = "nuclei." + templateID
		}
		return audit.ToolFinding{
			Source:          "external_tool",
			Tool:            "nuclei",
			Asset:           stringValue(raw, "matched-at"),
			Type:            templateID,
			SourceRuleID:    sourceRuleID,
			SourceRuleGroup: nucleiGroup(raw),
			Severity:        severity,
			Title:           title,
			Evidence:        raw,
			Recommendation:  "Ověřte nález proti cílové službě a aplikujte doporučení z Nuclei šablony nebo vendor dokumentace.",
			RawFile:         path,
		}, true
	})
}

func parseAmass(path string) ([]audit.ToolFinding, error) {
	return parseJSONLines(path, func(raw map[string]any) (audit.ToolFinding, bool) {
		name := stringValue(raw, "name")
		if name == "" {
			return audit.ToolFinding{}, false
		}
		return audit.ToolFinding{
			Source:        "external_tool",
			Tool:          "amass",
			Asset:         name,
			Type:          "subdomain",
			AtomicCheckID: "inventory.subdomains",
			SourceRuleID:  "amass.enum.passive-enumeration",
			Severity:      "info",
			Title:         "Discovered attack-surface name",
			Evidence:      raw,
			RawFile:       path,
		}, true
	})
}

func parseAmassText(path string) ([]audit.ToolFinding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	out := []audit.ToolFinding{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		name := strings.TrimSpace(scanner.Text())
		if name == "" || strings.ContainsAny(name, " \t") {
			continue
		}
		out = append(out, audit.ToolFinding{
			Source:        "external_tool",
			Tool:          "amass",
			Asset:         name,
			Type:          "subdomain",
			AtomicCheckID: "inventory.subdomains",
			SourceRuleID:  "amass.enum.passive-enumeration",
			Severity:      "info",
			Title:         "Discovered attack-surface name",
			Evidence:      map[string]any{"name": name},
			RawFile:       path,
		})
	}
	return out, scanner.Err()
}

func parseZAP(path string) ([]audit.ToolFinding, error) {
	var doc struct {
		Site []struct {
			Alerts []map[string]any `json:"alerts"`
		} `json:"site"`
	}
	if err := readJSON(path, &doc); err != nil {
		return nil, err
	}
	out := []audit.ToolFinding{}
	for _, site := range doc.Site {
		for _, alert := range site.Alerts {
			risk := strings.ToLower(stringValue(alert, "riskdesc"))
			if risk == "" {
				risk = strings.ToLower(stringValue(alert, "risk"))
			}
			severity := zapSeverity(risk)
			title := stringValue(alert, "alert")
			if title == "" {
				title = "ZAP baseline alert"
			}
			pluginID := stringValue(alert, "pluginid")
			sourceRuleID := ""
			if pluginID != "" {
				sourceRuleID = "zap." + pluginID
			}
			out = append(out, audit.ToolFinding{
				Source:         "external_tool",
				Tool:           "zap",
				Asset:          stringValue(alert, "url"),
				Type:           pluginID,
				SourceRuleID:   sourceRuleID,
				Severity:       severity,
				Title:          title,
				Evidence:       alert,
				Recommendation: firstNonEmpty(stringValue(alert, "solution"), "Review the ZAP alert and adjust the web application or headers."),
				RawFile:        path,
			})
		}
	}
	return out, nil
}

func parseTestSSL(path string) ([]audit.ToolFinding, error) {
	var rows []map[string]any
	if err := readJSON(path, &rows); err != nil {
		return nil, err
	}
	out := []audit.ToolFinding{}
	for _, row := range rows {
		severity := strings.ToLower(firstNonEmpty(stringValue(row, "severity"), stringValue(row, "finding")))
		if severity == "" || severity == "ok" || severity == "info" {
			continue
		}
		id := stringValue(row, "id")
		if id == "" {
			id = "testssl"
		}
		out = append(out, audit.ToolFinding{
			Source:         "external_tool",
			Tool:           "testssl",
			Asset:          stringValue(row, "ip"),
			Type:           id,
			SourceRuleID:   "testssl." + id,
			Severity:       normalizeSeverity(severity),
			Title:          firstNonEmpty(stringValue(row, "finding"), id),
			Evidence:       row,
			Recommendation: "Upravte TLS konfiguraci podle zjištění testssl.sh a ověřte podporované protokoly/ciphery.",
			RawFile:        path,
		})
	}
	return out, nil
}

func parseSimpleToolJSON(tool string) func(string) ([]audit.ToolFinding, error) {
	return func(path string) ([]audit.ToolFinding, error) {
		var rows []audit.ToolFinding
		if err := readJSON(path, &rows); err == nil {
			for i := range rows {
				rows[i].RawFile = path
				if rows[i].Source == "" {
					rows[i].Source = "external_tool"
				}
				if rows[i].Tool == "" {
					rows[i].Tool = tool
				}
			}
			return rows, nil
		}
		var row audit.ToolFinding
		if err := readJSON(path, &row); err != nil {
			return nil, err
		}
		row.RawFile = path
		if row.Source == "" {
			row.Source = "external_tool"
		}
		if row.Tool == "" {
			row.Tool = tool
		}
		if row.SourceRuleID == "" && row.Type != "" {
			row.SourceRuleID = tool + "." + row.Type
		}
		return []audit.ToolFinding{row}, nil
	}
}

func normalizeWithCatalog(findings []audit.ToolFinding) {
	cat, err := catalog.LoadEmbedded()
	if err != nil {
		return
	}
	for i := range findings {
		if findings[i].AtomicCheckID != "" {
			continue
		}
		source := catalogSource(findings[i].Tool)
		if source == "" || findings[i].SourceRuleID == "" {
			continue
		}
		if match, ok := cat.Resolver.Resolve(source, findings[i].SourceRuleID, findings[i].SourceRuleGroup); ok {
			findings[i].AtomicCheckID = match.CanonicalID
			findings[i].MappingConfidence = match.Confidence
		}
	}
}

func catalogSource(tool string) string {
	switch tool {
	case "nuclei":
		return "nuclei"
	case "zap":
		return "zap"
	case "testssl":
		return "testssl"
	case "subfinder", "httpx", "naabu":
		return "projectdiscovery"
	case "amass":
		return "amass"
	case "internetnl":
		return "internetnl"
	case "greenbone":
		return "greenbone"
	default:
		return tool
	}
}

func nucleiGroup(raw map[string]any) string {
	path := firstNonEmpty(
		stringValue(raw, "template-path"),
		stringValue(raw, "template-url"),
		stringValue(raw, "template"),
	)
	path = strings.ReplaceAll(path, "\\", "/")
	if path == "" {
		return ""
	}
	parts := strings.Split(path, "/")
	for i, part := range parts {
		switch part {
		case "http", "network", "cloud", "file", "code", "javascript", "headless", "dast", "ssl", "dns":
			end := i + 2
			if end > len(parts) {
				end = len(parts)
			}
			return strings.Join(parts[i:end], "/")
		}
	}
	if len(parts) >= 2 {
		return strings.Join(parts[:2], "/")
	}
	return strings.TrimSuffix(path, ".yaml")
}

func parseJSONLines(path string, convert func(map[string]any) (audit.ToolFinding, bool)) ([]audit.ToolFinding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	out := []audit.ToolFinding{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}
		if finding, ok := convert(raw); ok {
			out = append(out, finding)
		}
	}
	return out, scanner.Err()
}

func readJSON(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func stringValue(raw map[string]any, key string) string {
	if raw == nil {
		return ""
	}
	switch v := raw[key].(type) {
	case string:
		return v
	case float64:
		return strconv.Itoa(int(v))
	case json.Number:
		return v.String()
	default:
		return ""
	}
}

func intValue(raw map[string]any, key string) int {
	if raw == nil {
		return 0
	}
	switch v := raw[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	case string:
		i, _ := strconv.Atoi(v)
		return i
	default:
		return 0
	}
}

func zapSeverity(risk string) string {
	switch {
	case strings.Contains(risk, "high"):
		return "high"
	case strings.Contains(risk, "medium"):
		return "medium"
	case strings.Contains(risk, "low"):
		return "low"
	default:
		return "info"
	}
}

func normalizeSeverity(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "critical", "high", "medium", "low", "info":
		return value
	case "warning", "warn":
		return "medium"
	case "not ok", "bad", "failed", "fail":
		return "high"
	default:
		return "info"
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
