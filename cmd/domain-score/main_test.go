package main

import (
	"bytes"
	"strings"
	"testing"
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
