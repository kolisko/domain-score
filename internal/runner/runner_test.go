package runner

import (
	"context"
	"testing"

	"github.com/kolisko/domain-score/internal/audit"
)

type fakeCheck struct {
	meta audit.CheckMeta
}

func (f fakeCheck) Meta() audit.CheckMeta { return f.meta }
func (f fakeCheck) Run(context.Context, audit.Target, audit.SharedEvidence) audit.Result {
	return audit.Result{CheckID: f.meta.ID, Category: f.meta.Category, Status: audit.StatusPass, Weight: f.meta.Weight}
}

func TestSelectSkipsAggressiveByDefault(t *testing.T) {
	checks := []audit.Check{
		fakeCheck{meta: audit.CheckMeta{ID: "safe.one", Mode: audit.ModeSafe, Weight: 1}},
		fakeCheck{meta: audit.CheckMeta{ID: "aggressive.one", Mode: audit.ModeAggressive, Weight: 1}},
	}
	got, err := Select(checks, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Meta().ID != "safe.one" {
		t.Fatalf("selected %#v", got)
	}
}

func TestSelectEnablesAggressiveExplicitly(t *testing.T) {
	checks := []audit.Check{
		fakeCheck{meta: audit.CheckMeta{ID: "safe.one", Mode: audit.ModeSafe, Weight: 1}},
		fakeCheck{meta: audit.CheckMeta{ID: "aggressive.one", Mode: audit.ModeAggressive, Weight: 1}},
	}
	got, err := Select(checks, Options{Enable: []string{"aggressive.one"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("selected %d checks, want 2", len(got))
	}
}

func TestSelectWeightOverrides(t *testing.T) {
	checks := []audit.Check{fakeCheck{meta: audit.CheckMeta{ID: "safe.one", Mode: audit.ModeSafe, Weight: 1}}}
	got, err := Select(checks, Options{WeightsYAML: []byte("weights:\n  safe.one: 7\n")})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Meta().Weight != 7 {
		t.Fatalf("weight = %d, want 7", got[0].Meta().Weight)
	}
}

func TestSelectOneCheck(t *testing.T) {
	checks := []audit.Check{
		fakeCheck{meta: audit.CheckMeta{ID: "safe.one", Mode: audit.ModeSafe, Weight: 1}},
		fakeCheck{meta: audit.CheckMeta{ID: "safe.two", Mode: audit.ModeSafe, Weight: 1}},
	}
	got, err := Select(checks, Options{CheckID: "safe.two"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Meta().ID != "safe.two" {
		t.Fatalf("selected %#v", got)
	}
}

func TestSelectOneAggressiveCheckWithoutProfile(t *testing.T) {
	checks := []audit.Check{
		fakeCheck{meta: audit.CheckMeta{ID: "aggressive.one", Mode: audit.ModeAggressive, Weight: 1}},
	}
	got, err := Select(checks, Options{CheckID: "aggressive.one"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("selected %d checks, want 1", len(got))
	}
}

func TestSelectToolOnlyCatalogCheckDoesNotRunDefaultChecks(t *testing.T) {
	checks := []audit.Check{
		fakeCheck{meta: audit.CheckMeta{ID: "safe.one", Mode: audit.ModeSafe, Weight: 1}},
		fakeCheck{meta: audit.CheckMeta{ID: "safe.two", Mode: audit.ModeSafe, Weight: 1}},
	}
	got, err := Select(checks, Options{ReportCheckID: "auth.insecure_authentication_signal"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("selected %d internal checks for tool-only catalog check, want 0", len(got))
	}
}

func TestSelectToolChecksDoesNotRunDefaultChecks(t *testing.T) {
	checks := []audit.Check{
		fakeCheck{meta: audit.CheckMeta{ID: "safe.one", Mode: audit.ModeSafe, Weight: 1}},
		fakeCheck{meta: audit.CheckMeta{ID: "safe.two", Mode: audit.ModeSafe, Weight: 1}},
	}
	got, err := Select(checks, Options{ToolChecks: []string{"zap"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("selected %d internal checks for tool-checks mode, want 0", len(got))
	}
}

func TestAtomicToolResultUsesCatalogCheckID(t *testing.T) {
	result := atomicToolResult(audit.ToolObservation{
		Enabled:  true,
		Selected: []string{"naabu"},
		RawFiles: []string{"/tmp/raw/naabu.jsonl"},
		Findings: []audit.ToolFinding{{
			Tool:          "naabu",
			AtomicCheckID: "network.open_ports",
			SourceRuleID:  "projectdiscovery.naabu.port-scan",
			Severity:      "medium",
			Title:         "Open port 22",
		}},
	}, "network.open_ports")
	if result.CheckID != "network.open_ports" {
		t.Fatalf("CheckID = %q", result.CheckID)
	}
	if result.Status != audit.StatusFail {
		t.Fatalf("Status = %s, want fail", result.Status)
	}
	if result.Weight == 0 {
		t.Fatal("expected catalog weight")
	}
	if sources, ok := result.Evidence["sources"].([]string); !ok || len(sources) != 1 || sources[0] != "tool:naabu" {
		t.Fatalf("expected sources evidence, got %#v", result.Evidence["sources"])
	}
}

func TestAtomicToolResultsForFindingsExpandsCanonicalChecks(t *testing.T) {
	results := atomicToolResultsForFindings(audit.ToolObservation{
		Enabled:  true,
		Selected: []string{"zap"},
		RawFiles: []string{"/tmp/raw/zap.json"},
		Findings: []audit.ToolFinding{{
			Tool:          "zap",
			AtomicCheckID: "http.hsts_present",
			SourceRuleID:  "zap.10035",
			Severity:      "high",
			Title:         "Strict-Transport-Security Header Not Set",
		}},
	})
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if results[0].CheckID != "http.hsts_present" || results[0].Status != audit.StatusFail {
		t.Fatalf("result = %#v", results[0])
	}
}

func TestAtomicToolResultsForToolsIncludesPassingToolChecks(t *testing.T) {
	results := atomicToolResultsForTools(audit.ToolObservation{
		Enabled:  true,
		Selected: []string{"zap"},
		Statuses: []audit.ToolStatus{{
			Tool:   "zap",
			Status: "done",
		}},
		RawFiles: []string{"/tmp/raw/zap.json"},
	}, []string{"zap"})
	seen := map[string]audit.Result{}
	for _, result := range results {
		seen[result.CheckID] = result
	}
	got, ok := seen["auth.insecure_authentication_signal"]
	if !ok {
		t.Fatal("expected auth.insecure_authentication_signal in zap tool-checks results")
	}
	if got.Status != audit.StatusPass {
		t.Fatalf("status = %s, want pass", got.Status)
	}
}
