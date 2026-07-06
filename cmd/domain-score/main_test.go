package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kolisko/domain-score/internal/catalog"
	"github.com/spf13/cobra"
)

func TestSplitCSV(t *testing.T) {
	got := splitCSV("json, md,,")
	if len(got) != 2 || got[0] != "json" || got[1] != "md" {
		t.Fatalf("unexpected split: %#v", got)
	}
}

func TestToolsListCommand(t *testing.T) {
	cmd := toolsCommand()
	cmd.SetArgs([]string{"list"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"subfinder", "nuclei", "greenbone", "projectdiscovery"} {
		if !strings.Contains(text, want) {
			t.Fatalf("tools list missing %q:\n%s", want, text)
		}
	}
}

func TestListInternalChecksCommand(t *testing.T) {
	cmd := listCommand()
	cmd.SetArgs([]string{"internal-checks"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"dns.dmarc", "http.hsts", "tls.certificate_valid"} {
		if !strings.Contains(text, want) {
			t.Fatalf("internal checks output missing %q:\n%s", want, text)
		}
	}
}

func TestListAllChecksCommand(t *testing.T) {
	cmd := listCommand()
	cmd.SetArgs([]string{"all-checks"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"network.open_ports", "inventory.subdomains", "vulnerability.known_cve_detected"} {
		if !strings.Contains(text, want) {
			t.Fatalf("all checks output missing %q:\n%s", want, text)
		}
	}
	for _, want := range []string{"SOURCE", "tool:naabu", "internal:dns.dmarc"} {
		if !strings.Contains(text, want) {
			t.Fatalf("all checks output missing source %q:\n%s", want, text)
		}
	}
}

func TestListToolChecksCommand(t *testing.T) {
	cmd := listCommand()
	cmd.SetArgs([]string{"tool-checks"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"SOURCE", "network.open_ports", "tool:naabu", "vulnerability.known_cve_detected"} {
		if !strings.Contains(text, want) {
			t.Fatalf("tool checks output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "dns.a_record") {
		t.Fatalf("tool checks output includes internal-only check:\n%s", text)
	}
}

func TestListSourceCatalogsCommand(t *testing.T) {
	cmd := listCommand()
	cmd.SetArgs([]string{"source-catalogs"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"nuclei", "greenbone", "nuclei-template-index"} {
		if !strings.Contains(text, want) {
			t.Fatalf("source catalogs output missing %q:\n%s", want, text)
		}
	}
}

func TestExplainCatalogCheck(t *testing.T) {
	cmd := explainCommand()
	cmd.SetArgs([]string{"network.open_ports"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Coverage:") {
		t.Fatalf("catalog explain missing coverage:\n%s", out.String())
	}
}

func TestResolveSingleCheckInternal(t *testing.T) {
	runID, reportID, tools, err := resolveSingleCheck("dns.dmarc", "none")
	if err != nil {
		t.Fatal(err)
	}
	if runID != "dns.dmarc" || reportID != "dns.dmarc" || tools != "" {
		t.Fatalf("resolve = %q %q %q", runID, reportID, tools)
	}
}

func TestResolveSingleCheckCatalogInternal(t *testing.T) {
	runID, reportID, tools, err := resolveSingleCheck("email.dmarc_present", "none")
	if err != nil {
		t.Fatal(err)
	}
	if runID != "dns.dmarc" || reportID != "email.dmarc_present" || tools != "" {
		t.Fatalf("resolve = %q %q %q", runID, reportID, tools)
	}
}

func TestResolveSingleCheckCatalogTool(t *testing.T) {
	runID, reportID, tools, err := resolveSingleCheck("network.open_ports", "none")
	if err != nil {
		t.Fatal(err)
	}
	if runID != "" || reportID != "network.open_ports" || tools != "naabu" {
		t.Fatalf("resolve = %q %q %q", runID, reportID, tools)
	}
}

func TestResolveSingleCheckCatalogUnsupported(t *testing.T) {
	runID, reportID, tools, err := resolveSingleCheck("tls.grade_summary", "none")
	if err != nil {
		t.Fatal(err)
	}
	if runID != "" || reportID != "tls.grade_summary" || tools != "" {
		t.Fatalf("resolve = %q %q %q", runID, reportID, tools)
	}
}

func TestResolveEveryCatalogCheckExplicitly(t *testing.T) {
	cat, err := catalog.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range cat.Checks {
		t.Run(check.ID, func(t *testing.T) {
			runID, reportID, tools, err := resolveSingleCheck(check.ID, "none")
			if err != nil {
				if !strings.Contains(err.Error(), "not runnable yet") {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if runID == "" && reportID == "" && tools == "" {
				t.Fatal("resolved to empty runtime path")
			}
			if reportID != "" && reportID != check.ID {
				t.Fatalf("reportID=%q, want %q", reportID, check.ID)
			}
		})
	}
}

func TestMissingScanArgPrintsScanHelp(t *testing.T) {
	out := executeExpectHelp(t, scanCommand())
	for _, want := range []string{"scan <domain-or-url>", "--check", "--tools", "--tool-checks", "--format"} {
		if !strings.Contains(out, want) {
			t.Fatalf("scan help missing %q:\n%s", want, out)
		}
	}
}

func TestMissingExplainArgPrintsExplainHelp(t *testing.T) {
	out := executeExpectHelp(t, explainCommand())
	if !strings.Contains(out, "explain <check-id>") {
		t.Fatalf("explain help missing command use:\n%s", out)
	}
}

func TestMissingHistoryShowArgPrintsSubcommandHelp(t *testing.T) {
	cmd := historyCommand()
	cmd.SetArgs([]string{"show"})
	out := executeExpectHelp(t, cmd)
	if !strings.Contains(out, "show <domain> [run|latest]") {
		t.Fatalf("history show help missing command use:\n%s", out)
	}
}

func TestMissingFlagValuePrintsCommandHelp(t *testing.T) {
	cmd := scanCommand()
	configureInputErrorHelp(cmd)
	cmd.SetArgs([]string{"--check"})
	out := executeExpectHelp(t, cmd)
	for _, want := range []string{"scan <domain-or-url>", "--check", "--tools"} {
		if !strings.Contains(out, want) {
			t.Fatalf("scan flag help missing %q:\n%s", want, out)
		}
	}
}

func executeExpectHelp(t *testing.T, cmd *cobra.Command) string {
	t.Helper()
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected helpError")
	} else if !isHelpError(err) {
		t.Fatalf("error = %T %v, want helpError", err, err)
	}
	if errOut.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", errOut.String())
	}
	return out.String()
}
