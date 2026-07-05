package catalog

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEmbeddedCatalog(t *testing.T) {
	cat, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Checks) != 299 {
		t.Fatalf("checks=%d, want 299", len(cat.Checks))
	}
	if len(cat.Mappings) != 558 {
		t.Fatalf("mappings=%d, want 558", len(cat.Mappings))
	}
	if len(cat.SourceCounts) != 21 {
		t.Fatalf("source counts=%d, want 21", len(cat.SourceCounts))
	}
	if _, ok := cat.FindCheck("network.open_ports"); !ok {
		t.Fatal("missing network.open_ports")
	}
}

func TestResolverMatchesExactAndGroup(t *testing.T) {
	resolver := NewResolver([]Mapping{
		{Source: "zap", MatchType: "exact", SourceID: "zap.10010", CanonicalID: "http.cookie_httponly_missing", Confidence: "high"},
		{Source: "nuclei", MatchType: "group", SourceID: "http/cves", CanonicalID: "vulnerability.known_cve_detected", Confidence: "high"},
		{Source: "nuclei", MatchType: "prefix", SourceID: "nuclei.", CanonicalID: "vulnerability.nuclei_template_match", Confidence: "low"},
	})
	if got, ok := resolver.Resolve("zap", "zap.10010"); !ok || got.CanonicalID != "http.cookie_httponly_missing" {
		t.Fatalf("zap resolve = %#v, %v", got, ok)
	}
	if got, ok := resolver.Resolve("nuclei", "nuclei.any", "http/cves/2024"); !ok || got.CanonicalID != "vulnerability.known_cve_detected" {
		t.Fatalf("nuclei resolve = %#v, %v", got, ok)
	}
}

func TestEmbeddedRuntimeCatalogMatchesRepoSources(t *testing.T) {
	repoCatalog, ok := FindRepoCatalogDir("")
	if !ok {
		t.Skip("repo catalog directory not found")
	}
	files := map[string]string{
		"data/atomic-checks.yaml":            "atomic-checks.yaml",
		"data/source-to-canonical-map.yaml":  "source-to-canonical-map.yaml",
		"data/source-access-policy.yaml":     "source-access-policy.yaml",
		"data/source-research-evidence.yaml": "source-research-evidence.yaml",
		"data/source-catalog-manifest.yaml":  filepath.Join("generated", "source-catalog-manifest.yaml"),
	}
	for embeddedPath, repoPath := range files {
		embeddedData, err := fs.ReadFile(embedded, embeddedPath)
		if err != nil {
			t.Fatal(err)
		}
		repoData, err := os.ReadFile(filepath.Join(repoCatalog, repoPath))
		if err != nil {
			t.Fatal(err)
		}
		if string(embeddedData) != string(repoData) {
			t.Fatalf("%s is out of sync with catalog/%s", embeddedPath, repoPath)
		}
	}
}
