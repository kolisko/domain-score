package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewRunDirResolveAndList(t *testing.T) {
	home := t.TempDir()
	t.Setenv(EnvHome, home)

	runDir, runID, err := NewRunDir("Example.COM")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(runDir, "raw")); err != nil {
		t.Fatalf("raw dir missing: %v", err)
	}

	data := []byte(`{"target":{"domain":"Example.COM"},"score":{"overall":87,"grade":"B","categories":{}},"evidence":{"tools":{"selected":["httpx","zap"]}}}`)
	if err := os.WriteFile(filepath.Join(runDir, "report.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	resolved, resolvedID, err := ResolveRun("example.com", "latest")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != runDir || resolvedID != runID {
		t.Fatalf("resolved = %q %q, want %q %q", resolved, resolvedID, runDir, runID)
	}

	runs, err := ListRuns("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].ID != runID || runs[0].Score != 87 || runs[0].Grade != "B" {
		t.Fatalf("unexpected runs: %#v", runs)
	}
}
