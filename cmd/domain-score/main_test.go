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
