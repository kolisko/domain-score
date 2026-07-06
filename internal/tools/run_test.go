package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kolisko/domain-score/internal/audit"
)

func TestRunUsesDockerPullRunAndParsesCache(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake docker shell script is POSIX-only")
	}
	binDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "docker.log")
	dockerPath := filepath.Join(binDir, "docker")
	script := `#!/usr/bin/env sh
set -eu
printf '%s\n' "$*" >> "` + logPath + `"
case "$1 $2" in
  "version --format")
    echo "24.0.0"
    exit 0
    ;;
  "image inspect")
    exit 1
    ;;
  "pull ghcr.io/kolisko/domain-score-tools:vtest")
    exit 0
    ;;
esac
if [ "$1" = "run" ]; then
  mount=""
  prev=""
  for arg in "$@"; do
    if [ "$prev" = "-v" ]; then
      mount="$arg"
      break
    fi
    prev="$arg"
  done
  work="${mount%%:*}"
  mkdir -p "$work/raw"
  printf '%s\n' '{"template-id":"fake","matched-at":"https://example.com","info":{"name":"Fake Finding","severity":"high"}}' > "$work/raw/nuclei.jsonl"
  exit 0
fi
exit 0
`
	if err := os.WriteFile(dockerPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath)

	got, err := Run(context.Background(), audit.Target{Domain: "example.com", URLs: []string{"https://example.com"}}, Options{
		Tools:    "nuclei",
		Image:    "ghcr.io/kolisko/domain-score-tools:vtest",
		Pull:     PullAuto,
		Timeout:  time.Minute,
		CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Observation.ImagePulled {
		t.Fatal("expected image to be pulled")
	}
	if len(got.Observation.Findings) != 1 {
		t.Fatalf("findings = %#v", got.Observation.Findings)
	}
	findingsData, err := os.ReadFile(filepath.Join(got.Observation.CacheDir, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cachedFindings []audit.ToolFinding
	if err := json.Unmarshal(findingsData, &cachedFindings); err != nil {
		t.Fatal(err)
	}
	if len(cachedFindings) != 1 || cachedFindings[0].Tool != "nuclei" || cachedFindings[0].Title != "Fake Finding" {
		t.Fatalf("cached findings = %#v", cachedFindings)
	}
	if len(got.Results) == 0 {
		t.Fatal("expected normalized audit results")
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(logData)
	for _, want := range []string{"version --format", "image inspect ghcr.io/kolisko/domain-score-tools:vtest", "pull ghcr.io/kolisko/domain-score-tools:vtest", "run --rm"} {
		if !strings.Contains(log, want) {
			t.Fatalf("docker log missing %q:\n%s", want, log)
		}
	}
}

func TestRunCacheRuntimeParsesExistingCacheWithoutDocker(t *testing.T) {
	cache := t.TempDir()
	raw := filepath.Join(cache, "raw")
	if err := os.MkdirAll(raw, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(raw, "nuclei.status"), `{"tool":"nuclei","status":"done","exit_code":0}`)
	writeTestFile(t, filepath.Join(raw, "nuclei.jsonl"), `{"template-id":"cve-test","template-path":"http/cves/2024/cve-test.yaml","matched-at":"https://app.example.com","info":{"name":"Test CVE","severity":"high"}}`+"\n")

	binDir := t.TempDir()
	dockerPath := filepath.Join(binDir, "docker")
	if err := os.WriteFile(dockerPath, []byte("#!/usr/bin/env sh\nexit 99\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath)

	got, err := Run(context.Background(), audit.Target{Domain: "example.com", URLs: []string{"https://example.com"}}, Options{
		Tools:    "nuclei",
		Runtime:  RuntimeCache,
		CacheDir: cache,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Observation.Runtime != RuntimeCache {
		t.Fatalf("runtime = %q, want cache", got.Observation.Runtime)
	}
	if len(got.Observation.Findings) != 1 {
		t.Fatalf("findings = %#v", got.Observation.Findings)
	}
	if got.Observation.Findings[0].AtomicCheckID != "vulnerability.known_cve_detected" {
		t.Fatalf("atomic_check_id = %q", got.Observation.Findings[0].AtomicCheckID)
	}
}

func TestRunCleansDockerContainerOnTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake docker shell script is POSIX-only")
	}
	binDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "docker.log")
	dockerPath := filepath.Join(binDir, "docker")
	script := `#!/usr/bin/env sh
set -eu
printf '%s\n' "$*" >> "` + logPath + `"
case "$1 $2" in
  "version --format")
    echo "24.0.0"
    exit 0
    ;;
  "image inspect")
    exit 0
    ;;
esac
if [ "$1" = "run" ]; then
  cidfile=""
  prev=""
  for arg in "$@"; do
    if [ "$prev" = "--cidfile" ]; then
      cidfile="$arg"
      break
    fi
    prev="$arg"
  done
  printf '%s\n' "fake-container" > "$cidfile"
  sleep 5
  exit 0
fi
if [ "$1" = "rm" ]; then
  exit 0
fi
exit 0
`
	if err := os.WriteFile(dockerPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath)

	got, err := Run(context.Background(), audit.Target{Domain: "example.com", URLs: []string{"https://example.com"}}, Options{
		Tools:    "nuclei",
		Image:    "ghcr.io/kolisko/domain-score-tools:vtest",
		Pull:     PullAuto,
		Timeout:  50 * time.Millisecond,
		CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Observation.Errors) == 0 {
		t.Fatal("expected timeout error in observation")
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(logData)
	if !strings.Contains(log, "rm -f fake-container") {
		t.Fatalf("docker cleanup missing from log:\n%s", log)
	}
}

func TestToolLogFilterHidesVerboseZapRows(t *testing.T) {
	var out bytes.Buffer
	filter := &toolLogFilter{dst: &out}
	_, _ = filter.Write([]byte("domain-score tools container: start zap\n"))
	_, _ = filter.Write([]byte("PASS: Cookie No HttpOnly Flag [10010]\n"))
	_, _ = filter.Write([]byte("WARN-NEW: Missing Anti-clickjacking Header [10020] x 1\n"))
	_, _ = filter.Write([]byte("\thttps://example.com (200 OK)\n"))
	filter.Flush()

	text := out.String()
	if !strings.Contains(text, "domain-score tools container: start zap") {
		t.Fatalf("progress line missing:\n%s", text)
	}
	for _, unwanted := range []string{"PASS:", "WARN-NEW:", "https://example.com"} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("verbose line %q was not filtered:\n%s", unwanted, text)
		}
	}
}
