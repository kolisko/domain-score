package report

import (
	"strings"
	"testing"

	"github.com/kolisko/domain-score/internal/audit"
)

func TestConsoleRendersAlignedStatusRows(t *testing.T) {
	out := string(Console(sampleReport(), ConsoleOptions{Color: false}))

	for _, want := range []string{
		"Domain Score: example.com  score=73/100 grade=C profile=safe aggressive=false",
		"STATUS  CATEGORY                CHECK",
		"PASS    dns                     dns.a_record",
		"WARN    http_security           http.hsts",
		"FAIL    seo                     seo.title",
		"ERROR   transparency            transparency.rdap",
		"N/A     reputation              reputation.virustotal",
		"Add HSTS.",
		"RDAP timeout",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("console output missing %q:\n%s", want, out)
		}
	}
}

func TestConsoleSortsByWeightByDefault(t *testing.T) {
	out := string(Console(sampleReport(), ConsoleOptions{Color: false}))

	assertOrder(t, out, "PASS    dns", "WARN    http_security", "FAIL    seo", "N/A     reputation", "ERROR   transparency")
}

func TestConsoleCanSortByStatus(t *testing.T) {
	out := string(Console(sampleReport(), ConsoleOptions{Color: false, Sort: SortStatus}))

	assertOrder(t, out, "FAIL    seo", "ERROR   transparency", "WARN    http_security", "PASS    dns", "N/A     reputation")
}

func TestConsoleColorizesStatusCells(t *testing.T) {
	out := string(Console(sampleReport(), ConsoleOptions{Color: true}))

	for _, want := range []string{
		"\033[32mPASS  \033[0m",
		"\033[33mWARN  \033[0m",
		"\033[31mFAIL  \033[0m",
		"\033[31mERROR \033[0m",
		"\033[90mN/A   \033[0m",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("colored console output missing %q:\n%s", want, out)
		}
	}
}

func TestMarkdownIncludesStatusMatrix(t *testing.T) {
	out := string(Markdown(sampleReport()))

	for _, want := range []string{
		"## Check table",
		"| PASS | WARN | FAIL | ERROR | N/A | Category | Check | Weight | Recommendation |",
		"| x |  |  |  |  | `dns` | `dns.a_record` A record | 5 | - |",
		"|  | x |  |  |  | `http_security` | `http.hsts` HSTS | 5 | Add HSTS. |",
		"|  |  | x |  |  | `seo` | `seo.title` Title | 4 | Add a title. |",
		"|  |  |  | x |  | `transparency` | `transparency.rdap` RDAP | 2 | - |",
		"|  |  |  |  | x | `reputation` | `reputation.virustotal` VirusTotal | 3 | - |",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("markdown output missing %q:\n%s", want, out)
		}
	}

	assertOrder(t, out, "`dns.a_record`", "`http.hsts`", "`seo.title`", "`reputation.virustotal`", "`transparency.rdap`")
}

func sampleReport() audit.Report {
	return audit.Report{
		Target:     audit.Target{Domain: "example.com"},
		Profile:    "safe",
		Aggressive: false,
		Score: audit.ScoreSummary{
			Overall: 73,
			Grade:   "C",
			Categories: map[string]audit.CategoryScore{
				"dns": {Score: 100, PassedWeight: 5, TotalWeight: 5, Checks: 1},
			},
		},
		Results: []audit.Result{
			{
				CheckID:  "dns.a_record",
				Title:    "A record",
				Category: "dns",
				Mode:     audit.ModeSafe,
				Status:   audit.StatusPass,
				Weight:   5,
			},
			{
				CheckID:        "http.hsts",
				Title:          "HSTS",
				Category:       "http_security",
				Mode:           audit.ModeSafe,
				Status:         audit.StatusWarn,
				Weight:         5,
				Recommendation: "Add HSTS.",
			},
			{
				CheckID:        "seo.title",
				Title:          "Title",
				Category:       "seo",
				Mode:           audit.ModeSafe,
				Status:         audit.StatusFail,
				Weight:         4,
				Recommendation: "Add a title.",
			},
			{
				CheckID:  "transparency.rdap",
				Title:    "RDAP",
				Category: "transparency",
				Mode:     audit.ModeSafe,
				Status:   audit.StatusError,
				Weight:   2,
				Error:    "RDAP timeout",
			},
			{
				CheckID:  "reputation.virustotal",
				Title:    "VirusTotal",
				Category: "reputation",
				Mode:     audit.ModeSafe,
				Status:   audit.StatusNotApplicable,
				Weight:   3,
			},
		},
	}
}

func assertOrder(t *testing.T, text string, values ...string) {
	t.Helper()
	last := -1
	for _, value := range values {
		next := strings.Index(text, value)
		if next == -1 {
			t.Fatalf("output missing %q:\n%s", value, text)
		}
		if next < last {
			t.Fatalf("%q appeared before previous value in output:\n%s", value, text)
		}
		last = next
	}
}
