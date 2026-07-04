package tools

import (
	"reflect"
	"testing"
)

func TestDefaultImageUsesPinnedToolsDigest(t *testing.T) {
	got := DefaultImage("v0.6.0")
	want := DefaultImageRef
	if got != want {
		t.Fatalf("DefaultImage = %q, want %q", got, want)
	}
}

func TestDefaultImageIsDecoupledFromCLIVersion(t *testing.T) {
	got := DefaultImage("0.6.0")
	want := DefaultImageRef
	if got != want {
		t.Fatalf("DefaultImage = %q, want %q", got, want)
	}
}

func TestDefaultImageDoesNotUseLatestForDev(t *testing.T) {
	got := DefaultImage("dev")
	want := DefaultImageRef
	if got != want {
		t.Fatalf("DefaultImage = %q, want %q", got, want)
	}
}

func TestExpandListSupportsAliasesAndDedupes(t *testing.T) {
	got, err := ExpandList("projectdiscovery,nuclei,tls")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"subfinder", "httpx", "naabu", "nuclei", "testssl"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExpandList = %#v, want %#v", got, want)
	}
}

func TestExpandListRejectsUnknownTool(t *testing.T) {
	if _, err := ExpandList("subfinder,nope"); err == nil {
		t.Fatal("expected error for unknown tool")
	}
}
