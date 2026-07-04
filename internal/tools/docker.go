package tools

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kolisko/domain-score/internal/audit"
)

type DockerRunner struct {
	Docker string
	Stdout *strings.Builder
	Stderr *strings.Builder
}

type RunResult struct {
	Observation audit.ToolObservation
	Results     []audit.Result
}

func Doctor(ctx context.Context, docker string) error {
	if strings.TrimSpace(docker) == "" {
		docker = "docker"
	}
	cmd := exec.CommandContext(ctx, docker, "version", "--format", "{{.Server.Version}}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Docker runtime is required for --tools. Install Docker Desktop or Docker Engine and make sure it is running: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func Pull(ctx context.Context, image string) error {
	if image == "" {
		return fmt.Errorf("tools image is empty")
	}
	statusf("pulling image %s", image)
	cmd := exec.CommandContext(ctx, "docker", "pull", image)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker pull %s failed: %v", image, err)
	}
	return nil
}

func Run(ctx context.Context, target audit.Target, opts Options) (RunResult, error) {
	selected, err := ExpandList(opts.Tools)
	if err != nil {
		return RunResult{}, err
	}
	if len(selected) == 0 {
		return RunResult{}, nil
	}
	runtime, err := NormalizeRuntime(opts.Runtime)
	if err != nil {
		return RunResult{}, err
	}
	pullPolicy, err := NormalizePullPolicy(opts.Pull)
	if err != nil {
		return RunResult{}, err
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}
	image := opts.Image
	if image == "" {
		image = DefaultImage(opts.Version)
	}
	cacheDir, err := prepareCacheDir(opts.CacheDir, target.Domain)
	if err != nil {
		return RunResult{}, err
	}
	obs := audit.ToolObservation{
		Enabled:    true,
		Runtime:    runtime,
		Image:      image,
		CacheDir:   cacheDir,
		Selected:   selected,
		PullPolicy: pullPolicy,
	}

	start := time.Now()
	statusf("selected tools: %s", strings.Join(selected, ","))
	statusf("cache: %s", cacheDir)
	statusf("checking Docker runtime")
	if err := Doctor(ctx, "docker"); err != nil {
		obs.Errors = append(obs.Errors, err.Error())
		obs.Duration = time.Since(start).String()
		statusf("Docker runtime check failed: %s", err)
		return RunResult{Observation: obs, Results: resultsFromObservation(obs)}, nil
	}
	statusf("checking tools image: %s", image)
	pulled, err := ensureImage(ctx, image, pullPolicy)
	if err != nil {
		obs.Errors = append(obs.Errors, err.Error())
		obs.Duration = time.Since(start).String()
		statusf("tools image check failed: %s", err)
		return RunResult{Observation: obs, Results: resultsFromObservation(obs)}, nil
	}
	obs.ImagePulled = pulled

	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	statusf("running tools container with timeout %s", opts.Timeout)
	if err := runContainer(runCtx, target, image, selected, cacheDir); err != nil {
		obs.Errors = append(obs.Errors, err.Error())
		statusf("tools container failed: %s", err)
	}

	statusf("reading raw outputs")
	rawFiles, _ := listRawFiles(cacheDir)
	obs.RawFiles = rawFiles
	findings, parseErrors := ParseCache(cacheDir)
	obs.Findings = findings
	obs.Errors = append(obs.Errors, parseErrors...)
	obs.Duration = time.Since(start).String()
	if len(obs.Errors) > 0 {
		statusf("completed with %d error(s) in %s", len(obs.Errors), obs.Duration)
	} else {
		statusf("completed in %s; findings=%d raw_files=%d", obs.Duration, len(obs.Findings), len(obs.RawFiles))
	}

	return RunResult{Observation: obs, Results: resultsFromObservation(obs)}, nil
}

func ensureImage(ctx context.Context, image string, pullPolicy string) (bool, error) {
	if pullPolicy == PullAlways {
		statusf("pull policy is always")
		return true, Pull(ctx, image)
	}
	inspect := exec.CommandContext(ctx, "docker", "image", "inspect", image)
	if err := inspect.Run(); err == nil {
		statusf("image found locally")
		return false, nil
	}
	if pullPolicy == PullNever {
		return false, fmt.Errorf("tools image %s is not available locally and --tools-pull=never was used", image)
	}
	statusf("image not found locally; first pull can take several minutes")
	return true, Pull(ctx, image)
}

func runContainer(ctx context.Context, target audit.Target, image string, selected []string, cacheDir string) error {
	url := "https://" + target.Domain
	if len(target.URLs) > 0 {
		url = target.URLs[0]
	}
	cidFile := filepath.Join(cacheDir, ".container.id")
	_ = os.Remove(cidFile)
	args := DockerRunArgs(image, cacheDir, target.Domain, url, selected, cidFile)
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		cleanupContainer(cidFile)
		return fmt.Errorf("tools container timed out: %w", ctx.Err())
	}
	if err != nil {
		cleanupContainer(cidFile)
		return fmt.Errorf("tools container failed: %v", err)
	}
	return nil
}

func DockerRunArgs(image string, cacheDir string, domain string, url string, selected []string, cidFile string) []string {
	return []string{
		"run",
		"--rm",
		"--cidfile", cidFile,
		"--read-only",
		"--tmpfs", "/tmp",
		"--network", "bridge",
		"-e", "HOME=/tmp",
		"-v", cacheDir + ":/work:rw",
		image,
		"scan",
		"--domain", domain,
		"--url", url,
		"--tools", strings.Join(selected, ","),
		"--out", "/work",
	}
}

func cleanupContainer(cidFile string) {
	data, err := os.ReadFile(cidFile)
	if err != nil {
		return
	}
	id := strings.TrimSpace(string(data))
	if id == "" {
		return
	}
	statusf("stopping tools container %s", id)
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cleanupCtx, "docker", "rm", "-f", id)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		statusf("failed to stop tools container %s: %v", id, err)
	}
}

func prepareCacheDir(base string, domain string) (string, error) {
	if base == "" {
		userCache, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(userCache, "domain-score", "tools")
	}
	cacheDir := filepath.Join(base, safePathPart(domain), "latest")
	if err := os.RemoveAll(cacheDir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Join(cacheDir, "raw"), 0o755); err != nil {
		return "", err
	}
	return cacheDir, nil
}

func safePathPart(value string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "..", "_")
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return "unknown"
	}
	return replacer.Replace(value)
}

func listRawFiles(cacheDir string) ([]string, error) {
	rawDir := filepath.Join(cacheDir, "raw")
	entries, err := os.ReadDir(rawDir)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		out = append(out, filepath.Join(rawDir, entry.Name()))
	}
	return out, nil
}

func statusf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "domain-score tools: "+format+"\n", args...)
}
