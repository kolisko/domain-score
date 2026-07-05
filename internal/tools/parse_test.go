package tools

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kolisko/domain-score/internal/audit"
)

func TestParseCacheParsesToolOutputs(t *testing.T) {
	cache := t.TempDir()
	raw := filepath.Join(cache, "raw")
	if err := os.MkdirAll(raw, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(raw, "subfinder.jsonl"), `{"host":"app.example.com"}`+"\n")
	writeTestFile(t, filepath.Join(raw, "httpx.jsonl"), `{"url":"https://app.example.com","status_code":200}`+"\n")
	writeTestFile(t, filepath.Join(raw, "naabu.jsonl"), `{"host":"app.example.com","port":22}`+"\n")
	writeTestFile(t, filepath.Join(raw, "nuclei.jsonl"), `{"template-id":"cve-test","matched-at":"https://app.example.com","info":{"name":"Test CVE","severity":"high"}}`+"\n")
	writeTestFile(t, filepath.Join(raw, "amass.txt"), "admin.example.com\n")
	writeTestFile(t, filepath.Join(raw, "zap.json"), `{"site":[{"alerts":[{"alert":"Missing Header","riskdesc":"Medium","url":"https://app.example.com","solution":"Add header"}]}]}`)
	writeTestFile(t, filepath.Join(raw, "internetnl.json"), `[{"tool":"internetnl","title":"Internet.nl score","severity":"info"}]`)

	findings, errors := ParseCache(cache)
	if len(errors) != 0 {
		t.Fatalf("ParseCache errors = %#v", errors)
	}
	if len(findings) != 7 {
		t.Fatalf("got %d findings, want 7: %#v", len(findings), findings)
	}
	if findings[3].Tool != "nuclei" || findings[3].Severity != "high" {
		t.Fatalf("unexpected nuclei finding: %#v", findings[3])
	}
}

func TestResultsFromObservationMapsFindingsToChecks(t *testing.T) {
	cache := t.TempDir()
	obs, errors := ParseCacheWithFixture(t, cache)
	if len(errors) != 0 {
		t.Fatalf("fixture parse errors = %#v", errors)
	}
	results := resultsFromObservation(obs)
	if len(results) == 0 {
		t.Fatal("expected tool results")
	}
	var nucleiStatus string
	for _, result := range results {
		if result.CheckID == "tools.nuclei_findings" {
			nucleiStatus = string(result.Status)
		}
	}
	if nucleiStatus != "fail" {
		t.Fatalf("tools.nuclei_findings status = %q, want fail", nucleiStatus)
	}
}

func TestResultsFromObservationRuntimeFailureDoesNotPassToolChecks(t *testing.T) {
	results := resultsFromObservation(audit.ToolObservation{
		Enabled:  true,
		Runtime:  RuntimeDocker,
		Image:    "ghcr.io/kolisko/domain-score-tools:v0.6.1",
		Selected: []string{"nuclei", "greenbone"},
		Errors:   []string{"docker pull failed"},
	})
	if len(results) != 1 {
		t.Fatalf("results len = %d, want 1: %#v", len(results), results)
	}
	if results[0].CheckID != "tools.runtime" || results[0].Status != audit.StatusError {
		t.Fatalf("unexpected runtime result: %#v", results[0])
	}
}

func TestResultsFromObservationDoesNotPassIncompleteSelectedTool(t *testing.T) {
	results := resultsFromObservation(audit.ToolObservation{
		Enabled:  true,
		Runtime:  RuntimeDocker,
		Image:    "ghcr.io/kolisko/domain-score-tools:vtest",
		Selected: []string{"zap"},
		RawFiles: []string{"/cache/raw/nuclei.status"},
		Errors:   []string{"tools container timed out"},
	})
	var got audit.Result
	for _, result := range results {
		if result.CheckID == "tools.zap_baseline_alerts" {
			got = result
			break
		}
	}
	if got.CheckID == "" {
		t.Fatalf("missing zap result: %#v", results)
	}
	if got.Status != audit.StatusError {
		t.Fatalf("zap status = %s, want error", got.Status)
	}
}

func TestParseStatusesParsesToolExitCodes(t *testing.T) {
	cache := t.TempDir()
	raw := filepath.Join(cache, "raw")
	if err := os.MkdirAll(raw, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(raw, "testssl.status"), `{"tool":"testssl","status":"done","exit_code":244,"elapsed_seconds":1}`)

	statuses, errors := ParseStatuses(cache)
	if len(errors) != 0 {
		t.Fatalf("ParseStatuses errors = %#v", errors)
	}
	if len(statuses) != 1 || statuses[0].Tool != "testssl" || statuses[0].ExitCode != 244 {
		t.Fatalf("unexpected statuses: %#v", statuses)
	}
}

func TestResultsFromObservationMarksFailedToolStatusAsError(t *testing.T) {
	results := resultsFromObservation(audit.ToolObservation{
		Enabled:  true,
		Runtime:  RuntimeDocker,
		Image:    "ghcr.io/kolisko/domain-score-tools:vtest",
		Selected: []string{"testssl"},
		Statuses: []audit.ToolStatus{{Tool: "testssl", Status: "done", ExitCode: 244}},
		RawFiles: []string{"/cache/raw/testssl.status", "/cache/raw/testssl.stderr"},
	})
	var got audit.Result
	for _, result := range results {
		if result.CheckID == "tools.testssl_findings" {
			got = result
			break
		}
	}
	if got.CheckID == "" {
		t.Fatalf("missing testssl result: %#v", results)
	}
	if got.Status != audit.StatusError {
		t.Fatalf("testssl status = %s, want error", got.Status)
	}
}

func ParseCacheWithFixture(t *testing.T, cache string) (audit.ToolObservation, []string) {
	t.Helper()
	raw := filepath.Join(cache, "raw")
	if err := os.MkdirAll(raw, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(raw, "nuclei.jsonl"), `{"template-id":"cve-test","matched-at":"https://app.example.com","info":{"name":"Test CVE","severity":"high"}}`+"\n")
	findings, errors := ParseCache(cache)
	return audit.ToolObservation{Enabled: true, Findings: findings}, errors
}

func writeTestFile(t *testing.T, path string, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}
