package report

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/kolisko/domain-score/internal/audit"
)

func Markdown(r audit.Report) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# Domain Score report: %s\n\n", r.Target.Domain)
	fmt.Fprintf(&b, "- Generated: %s\n", r.GeneratedAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(&b, "- Profile: `%s`\n", r.Profile)
	fmt.Fprintf(&b, "- Aggressive checks: `%t`\n", r.Aggressive)
	fmt.Fprintf(&b, "- Overall score: **%d/100 (%s)**\n\n", r.Score.Overall, r.Score.Grade)

	fmt.Fprintln(&b, "## Category scores")
	cats := make([]string, 0, len(r.Score.Categories))
	for c := range r.Score.Categories {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for _, c := range cats {
		cs := r.Score.Categories[c]
		fmt.Fprintf(&b, "- `%s`: %d/100 (%d/%d weight, %d checks)\n", c, cs.Score, cs.PassedWeight, cs.TotalWeight, cs.Checks)
	}

	fmt.Fprintln(&b, "\n## Check table")
	fmt.Fprintln(&b, "| PASS | WARN | FAIL | ERROR | N/A | Category | Check | Weight | Recommendation |")
	fmt.Fprintln(&b, "|:---:|:---:|:---:|:---:|:---:|---|---|---:|---|")
	for _, res := range r.Results {
		pass, warn, fail, errMark, na := markdownStatusMarks(res.Status)
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | `%s` | `%s` %s | %d | %s |\n",
			pass,
			warn,
			fail,
			errMark,
			na,
			res.Category,
			res.CheckID,
			escapeTable(res.Title),
			res.Weight,
			escapeTable(shortRecommendation(res.Recommendation)),
		)
	}

	fmt.Fprintln(&b, "\n## Top findings")
	findings := append([]audit.Result(nil), r.Results...)
	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].ScoreImpact > findings[j].ScoreImpact
	})
	count := 0
	for _, res := range findings {
		if res.Status != audit.StatusFail && res.Status != audit.StatusWarn {
			continue
		}
		fmt.Fprintf(&b, "- **%s** `%s` [%s]: %s\n", res.Title, res.CheckID, res.Status, res.Recommendation)
		count++
		if count == 10 {
			break
		}
	}
	if count == 0 {
		fmt.Fprintln(&b, "- No warning or failing findings.")
	}

	fmt.Fprintln(&b, "\n## All checks")
	for _, res := range r.Results {
		fmt.Fprintf(&b, "### %s `%s`\n\n", res.Title, res.CheckID)
		fmt.Fprintf(&b, "- Category: `%s`\n", res.Category)
		fmt.Fprintf(&b, "- Mode: `%s`\n", res.Mode)
		fmt.Fprintf(&b, "- Status: `%s`\n", res.Status)
		fmt.Fprintf(&b, "- Weight: `%d`\n", res.Weight)
		if res.Recommendation != "" {
			fmt.Fprintf(&b, "- Recommendation: %s\n", res.Recommendation)
		}
		if res.Error != "" {
			fmt.Fprintf(&b, "- Error: `%s`\n", strings.ReplaceAll(res.Error, "\n", " "))
		}
		fmt.Fprintln(&b)
	}
	return b.Bytes()
}

func markdownStatusMarks(status audit.Status) (string, string, string, string, string) {
	switch status {
	case audit.StatusPass:
		return "x", "", "", "", ""
	case audit.StatusWarn:
		return "", "x", "", "", ""
	case audit.StatusFail:
		return "", "", "x", "", ""
	case audit.StatusError:
		return "", "", "", "x", ""
	case audit.StatusNotApplicable:
		return "", "", "", "", "x"
	default:
		return "", "", "", "", ""
	}
}

func shortRecommendation(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\n", " "))
	if len(value) > 120 {
		return value[:117] + "..."
	}
	if value == "" {
		return "-"
	}
	return value
}

func escapeTable(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}
