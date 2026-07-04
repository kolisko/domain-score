package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAssetName(t *testing.T) {
	tests := []struct {
		goos string
		want string
	}{
		{goos: "darwin", want: "domain-score_0.1.1_darwin_arm64.tar.gz"},
		{goos: "linux", want: "domain-score_0.1.1_linux_arm64.tar.gz"},
		{goos: "windows", want: "domain-score_0.1.1_windows_arm64.zip"},
	}
	for _, test := range tests {
		got := AssetName("v0.1.1", test.goos, "arm64")
		if got != test.want {
			t.Fatalf("AssetName=%q, want %q", got, test.want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a    string
		b    string
		want int
	}{
		{a: "v0.2.3", b: "v0.2.4", want: -1},
		{a: "0.2.4", b: "v0.2.4", want: 0},
		{a: "v0.2.10", b: "v0.2.9", want: 1},
		{a: "v1.0.0", b: "v1.0.0", want: 0},
	}
	for _, test := range tests {
		got := CompareVersions(test.a, test.b)
		if got != test.want {
			t.Fatalf("CompareVersions(%q, %q)=%d, want %d", test.a, test.b, got, test.want)
		}
	}
}

func TestIsReleaseVersionAcceptsGoReleaserVersionWithoutV(t *testing.T) {
	if !IsReleaseVersion("0.6.5") {
		t.Fatal("expected bare GoReleaser version to be treated as release version")
	}
}

func TestUpdateSkipsSameBareCurrentVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v0.6.5","assets":[]}`))
	}))
	defer server.Close()

	var out bytes.Buffer
	err := Update(context.Background(), Config{
		CurrentVersion: "0.6.5",
		APIURL:         server.URL,
		Client:         server.Client(),
	}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "already up to date") {
		t.Fatalf("expected already up to date output, got:\n%s", out.String())
	}
}

func TestCheckDetectsOutdatedReleaseVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v0.2.4","html_url":"https://example.test/release","assets":[]}`))
	}))
	defer server.Close()

	got, err := Check(context.Background(), Config{
		CurrentVersion: "v0.2.3",
		APIURL:         server.URL,
		Client:         server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Outdated || got.LatestVersion != "v0.2.4" {
		t.Fatalf("unexpected check result: %+v", got)
	}
}

func TestCheckSkipsDevBuildAsOutdated(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v9.9.9","assets":[]}`))
	}))
	defer server.Close()

	got, err := Check(context.Background(), Config{
		CurrentVersion: "dev",
		APIURL:         server.URL,
		Client:         server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Outdated {
		t.Fatalf("dev build should not be marked outdated: %+v", got)
	}
}

func TestUpdateExtractsArchiveAndReplacesExecutable(t *testing.T) {
	dir := t.TempDir()
	exePath := filepath.Join(dir, "domain-score")
	if err := os.WriteFile(exePath, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := tarGz(t, "domain-score", []byte("new"))
	digest := sha256.Sum256(payload)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"tag_name":"v0.2.4","assets":[{"name":"domain-score_0.2.4_linux_amd64.tar.gz","browser_download_url":"%s/asset","digest":"sha256:%x","size":%d}]}`, serverURL(r), digest, len(payload))
		case "/asset":
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	err := Update(context.Background(), Config{
		CurrentVersion: "v0.2.3",
		APIURL:         server.URL + "/latest",
		ExecutablePath: exePath,
		GOOS:           "linux",
		GOARCH:         "amd64",
		Client:         server.Client(),
	}, &out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"update: checking latest release",
		"update: latest=v0.2.4 current=v0.2.3 asset=domain-score_0.2.4_linux_amd64.tar.gz",
		"update: downloading domain-score_0.2.4_linux_amd64.tar.gz",
		"update: downloaded domain-score_0.2.4_linux_amd64.tar.gz",
		"100.0%",
		"update: verifying sha256 for domain-score_0.2.4_linux_amd64.tar.gz",
		"update: replacing executable",
		"domain-score updated to v0.2.4",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("update output missing %q in:\n%s", want, out.String())
		}
	}
	got, err := os.ReadFile(exePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("updated executable=%q, want new", string(got))
	}
	leftovers, err := filepath.Glob(filepath.Join(dir, ".domain-score.update.*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("unexpected temp leftovers: %v", leftovers)
	}
}

func TestUpdateRejectsDigestMismatchAndCleansTemp(t *testing.T) {
	dir := t.TempDir()
	exePath := filepath.Join(dir, "domain-score")
	if err := os.WriteFile(exePath, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := tarGz(t, "domain-score", []byte("new"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"tag_name":"v0.2.4","assets":[{"name":"domain-score_0.2.4_linux_amd64.tar.gz","browser_download_url":"%s/asset","digest":"sha256:0000","size":%d}]}`, serverURL(r), len(payload))
		case "/asset":
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	err := Update(context.Background(), Config{
		CurrentVersion: "v0.2.3",
		APIURL:         server.URL + "/latest",
		ExecutablePath: exePath,
		GOOS:           "linux",
		GOARCH:         "amd64",
		Client:         server.Client(),
	}, os.Stderr)
	if err == nil {
		t.Fatal("expected digest mismatch")
	}
	got, err := os.ReadFile(exePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old" {
		t.Fatalf("executable changed after failed update: %q", string(got))
	}
	leftovers, err := filepath.Glob(filepath.Join(dir, ".domain-score.update.*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("unexpected temp leftovers: %v", leftovers)
	}
}

func tarGz(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func serverURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}
