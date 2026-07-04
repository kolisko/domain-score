package tools

import (
	"context"
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
