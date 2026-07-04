package report

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/kolisko/domain-score/internal/audit"
)

type ConsoleOptions struct {
	Color bool
	Sort  string
}

func Console(r audit.Report, opts ConsoleOptions) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "Domain Score: %s  score=%d/100 grade=%s profile=%s aggressive=%t\n\n", r.Target.Domain, r.Score.Overall, r.Score.Grade, r.Profile, r.Aggressive)
	fmt.Fprintf(&b, "%-6s  %-22s  %-42s  %-8s  %s\n", "STATUS", "CATEGORY", "CHECK", "WEIGHT", "TITLE")
	fmt.Fprintf(&b, "%-6s  %-22s  %-42s  %-8s  %s\n", "------", "----------------------", "------------------------------------------", "------", "-----")
	for _, res := range sortedResults(r.Results, opts.Sort) {
		fmt.Fprintf(&b, "%s  %-22s  %-42s  %6d    %s\n",
			consoleStatusCell(res.Status, opts.Color, 6),
			truncate(res.Category, 22),
			truncate(res.CheckID, 42),
			res.Weight,
			res.Title,
		)
		if res.Status == audit.StatusWarn || res.Status == audit.StatusFail || res.Status == audit.StatusError {
			detail := res.Recommendation
			if res.Error != "" {
				detail = res.Error
			}
			if strings.TrimSpace(detail) != "" {
				fmt.Fprintf(&b, "        %-22s  %-42s            %s\n", "", "", truncate(detail, 110))
			}
		}
	}
	return b.Bytes()
}

func consoleStatusCell(status audit.Status, color bool, width int) string {
	label := strings.ToUpper(string(status))
	switch status {
	case audit.StatusNotApplicable:
		label = "N/A"
	case audit.StatusPass:
		label = "PASS"
	case audit.StatusWarn:
		label = "WARN"
	case audit.StatusFail:
		label = "FAIL"
	case audit.StatusError:
		label = "ERROR"
	}
	padded := fmt.Sprintf("%-*s", width, label)
	if !color {
		return padded
	}
	switch status {
	case audit.StatusPass:
		return "\033[32m" + padded + "\033[0m"
	case audit.StatusWarn:
		return "\033[33m" + padded + "\033[0m"
	case audit.StatusFail, audit.StatusError:
		return "\033[31m" + padded + "\033[0m"
	case audit.StatusNotApplicable:
		return "\033[90m" + padded + "\033[0m"
	default:
		return padded
	}
}

func truncate(value string, maxLen int) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\n", " "))
	if maxLen <= 0 || len(value) <= maxLen {
		return value
	}
	if maxLen <= 3 {
		return value[:maxLen]
	}
	return value[:maxLen-3] + "..."
}
