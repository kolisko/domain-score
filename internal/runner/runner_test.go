package runner

import (
	"context"
	"testing"

	"github.com/kolisko/domain-score/internal/audit"
	"github.com/kolisko/domain-score/internal/catalog"
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

func TestUnsupportedCatalogResultIsNotApplicable(t *testing.T) {
	result := unsupportedCatalogResult("tls.grade_summary")
	if result.CheckID != "tls.grade_summary" {
		t.Fatalf("CheckID = %q", result.CheckID)
	}
	if result.Status != audit.StatusNotApplicable {
		t.Fatalf("Status = %s, want not_applicable", result.Status)
	}
	if result.ScoreImpact != 0 {
		t.Fatalf("ScoreImpact = %d, want 0", result.ScoreImpact)
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

func TestAtomicToolResultsForToolsDoesNotFakePassExternalRawChecks(t *testing.T) {
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
	if got.Status != audit.StatusNotApplicable {
		t.Fatalf("status = %s, want not_applicable", got.Status)
	}
}

func TestAtomicToolResultsForToolsCanPassImplementedChecksWithNegativeEvidence(t *testing.T) {
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
	got, ok := seen["http.frame_protection_missing"]
	if !ok {
		t.Fatal("expected http.frame_protection_missing in zap tool-checks results")
	}
	if got.Status != audit.StatusPass {
		t.Fatalf("status = %s, want pass", got.Status)
	}
}

func TestAtomicToolResultsForToolsDoesNotPassPlannedChecks(t *testing.T) {
	results := atomicToolResultsForTools(audit.ToolObservation{
		Enabled:  true,
		Selected: []string{"nuclei"},
		Statuses: []audit.ToolStatus{{
			Tool:   "nuclei",
			Status: "done",
		}},
		RawFiles: []string{"/tmp/raw/nuclei.jsonl"},
	}, []string{"nuclei"})
	seen := map[string]audit.Result{}
	for _, result := range results {
		seen[result.CheckID] = result
	}
	got, ok := seen["nuclei.cloud_misconfiguration"]
	if !ok {
		t.Fatal("expected nuclei.cloud_misconfiguration in nuclei tool-checks results")
	}
	if got.Status != audit.StatusNotApplicable {
		t.Fatalf("status = %s, want not_applicable", got.Status)
	}
}

func TestAtomicToolResultsForToolsDoesNotPassNonOperationalWrappers(t *testing.T) {
	results := atomicToolResultsForTools(audit.ToolObservation{
		Enabled:  true,
		Selected: []string{"internetnl"},
		Statuses: []audit.ToolStatus{{
			Tool:   "internetnl",
			Status: "done",
		}},
		RawFiles: []string{"/tmp/raw/internetnl.json"},
		Findings: []audit.ToolFinding{{
			Tool:  "internetnl",
			Type:  "tool_status",
			Title: "Internet.nl local source is present in the tools image",
		}},
	}, []string{"internetnl"})
	for _, result := range results {
		if result.Status == audit.StatusPass {
			t.Fatalf("%s returned pass without operational internetnl evidence", result.CheckID)
		}
	}
}

func TestAtomicToolResultsForAllCatalogChecksAvoidFakePass(t *testing.T) {
	cat, err := catalog.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	tools := []string{"subfinder", "httpx", "naabu", "nuclei", "amass", "testssl", "zap", "internetnl", "greenbone"}
	obs := audit.ToolObservation{
		Enabled:  true,
		Selected: tools,
	}
	for _, tool := range tools {
		obs.Statuses = append(obs.Statuses, audit.ToolStatus{Tool: tool, Status: "done"})
		obs.RawFiles = append(obs.RawFiles, "/tmp/raw/"+tool+".json")
	}
	results := atomicToolResultsForTools(obs, tools)
	if len(results) == 0 {
		t.Fatal("expected tool-backed catalog results")
	}
	checksByID := map[string]catalog.Check{}
	for _, check := range cat.Checks {
		checksByID[check.ID] = check
	}
	for _, result := range results {
		check := checksByID[result.CheckID]
		if result.Status == audit.StatusPass && !canPassWithoutFinding(check) {
			t.Fatalf("%s returned fake pass with coverage_status=%s", result.CheckID, check.CoverageStatus)
		}
	}
}
