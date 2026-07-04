package report

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/kolisko/domain-score/internal/audit"
)

type MarkdownOptions struct {
	Sort         string
	Details      string
	DetailsCheck string
}

func Markdown(r audit.Report) []byte {
	return MarkdownWithOptions(r, MarkdownOptions{Sort: SortWeight})
}

func MarkdownWithOptions(r audit.Report, opts MarkdownOptions) []byte {
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
	for _, res := range sortedResults(r.Results, opts.Sort) {
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

	writeMarkdownDetails(&b, r, opts)

	fmt.Fprintln(&b, "\n## All checks")
	for _, res := range sortedResults(r.Results, opts.Sort) {
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

func writeMarkdownDetails(b *bytes.Buffer, r audit.Report, opts MarkdownOptions) {
	results := detailResults(r.Results, opts.Sort, opts.Details, opts.DetailsCheck)
	if len(results) == 0 {
		return
	}
	fmt.Fprintln(b, "\n## Detailed checks")
	for _, res := range results {
		fmt.Fprintf(b, "\n### %s `%s`\n\n", res.Title, res.CheckID)
		fmt.Fprintf(b, "- Status: `%s`\n", res.Status)
		fmt.Fprintf(b, "- Category: `%s`\n", res.Category)
		fmt.Fprintf(b, "- Weight: `%d`\n", res.Weight)
		fmt.Fprintf(b, "- Severity: `%s`\n", res.Severity)
		fmt.Fprintf(b, "- Mode: `%s`\n\n", res.Mode)
		fmt.Fprintf(b, "**What is wrong:** %s\n\n", escapeMarkdownText(problemText(res)))
		fmt.Fprintf(b, "**Why it matters:** %s\n\n", escapeMarkdownText(riskText(res)))
		fmt.Fprintln(b, "**Evidence:**")
		for _, line := range evidenceLines(res) {
			fmt.Fprintf(b, "- `%s`\n", escapeBackticks(line))
		}
		fmt.Fprintf(b, "\n**How to fix:** %s\n\n", escapeMarkdownText(fixText(res)))
		fmt.Fprintf(b, "**Recommended target state:** %s\n", escapeMarkdownText(targetStateText(res, r.Target.Domain)))
	}
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

func escapeMarkdownText(value string) string {
	return strings.ReplaceAll(value, "\n", " ")
}

func escapeBackticks(value string) string {
	return strings.ReplaceAll(value, "`", "\\`")
}
