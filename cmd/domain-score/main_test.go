package main

import "testing"

func TestSplitCSV(t *testing.T) {
	got := splitCSV("json, md,,")
	if len(got) != 2 || got[0] != "json" || got[1] != "md" {
		t.Fatalf("unexpected split: %#v", got)
	}
}
