package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kolisko/domain-score/internal/audit"
)

const EnvHome = "DOMAIN_SCORE_HOME"

type RunInfo struct {
	Domain      string
	ID          string
	Path        string
	GeneratedAt time.Time
	Score       int
	Grade       string
	Tools       []string
}

func HomeDir() (string, error) {
	if home := strings.TrimSpace(os.Getenv(EnvHome)); home != "" {
		return home, nil
	}
	userHome, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(userHome, ".domain-score"), nil
}

func RunsDir(home string) string {
	return filepath.Join(home, "runs")
}

func DomainRunsDir(home string, domain string) string {
	return filepath.Join(RunsDir(home), SafePathPart(domain))
}

func NewRunDir(domain string) (string, string, error) {
	home, err := HomeDir()
	if err != nil {
		return "", "", err
	}
	domainDir := DomainRunsDir(home, domain)
	runID := time.Now().UTC().Format("20060102T150405Z")
	runDir := filepath.Join(domainDir, runID)
	for suffix := 2; ; suffix++ {
		if err := os.MkdirAll(domainDir, 0o755); err != nil {
			return "", "", err
		}
		if err := os.Mkdir(runDir, 0o755); err == nil {
			if err := os.MkdirAll(filepath.Join(runDir, "raw"), 0o755); err != nil {
				return "", "", err
			}
			if err := updateLatest(domainDir, runID); err != nil {
				return "", "", err
			}
			return runDir, runID, nil
		} else if !errors.Is(err, os.ErrExist) {
			return "", "", err
		}
		runID = fmt.Sprintf("%s-%02d", time.Now().UTC().Format("20060102T150405Z"), suffix)
		runDir = filepath.Join(domainDir, runID)
	}
}

func ResolveRun(domain string, runID string) (string, string, error) {
	home, err := HomeDir()
	if err != nil {
		return "", "", err
	}
	domainDir := DomainRunsDir(home, domain)
	if strings.TrimSpace(runID) == "" || runID == "latest" {
		data, err := os.ReadFile(filepath.Join(domainDir, "latest.txt"))
		if err != nil {
			return "", "", fmt.Errorf("latest run for %s not found", domain)
		}
		runID = strings.TrimSpace(string(data))
	}
	if runID == "" {
		return "", "", fmt.Errorf("latest run for %s is empty", domain)
	}
	if strings.ContainsAny(runID, `/\`) || strings.Contains(runID, "..") {
		return "", "", fmt.Errorf("invalid run id %q", runID)
	}
	runDir := filepath.Join(domainDir, runID)
	if _, err := os.Stat(runDir); err != nil {
		return "", "", err
	}
	return runDir, runID, nil
}

func ListRuns(domain string) ([]RunInfo, error) {
	home, err := HomeDir()
	if err != nil {
		return nil, err
	}
	domains := []string{domain}
	if strings.TrimSpace(domain) == "" {
		entries, err := os.ReadDir(RunsDir(home))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, nil
			}
			return nil, err
		}
		domains = nil
		for _, entry := range entries {
			if entry.IsDir() {
				domains = append(domains, entry.Name())
			}
		}
	}
	out := []RunInfo{}
	for _, d := range domains {
		entries, err := os.ReadDir(DomainRunsDir(home, d))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		for _, entry := range entries {
			if !entry.IsDir() || entry.Name() == "latest" {
				continue
			}
			out = append(out, readRunInfo(d, filepath.Join(DomainRunsDir(home, d), entry.Name()), entry.Name()))
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].ID > out[j].ID
	})
	return out, nil
}

func ReadReport(runDir string) (audit.Report, error) {
	var r audit.Report
	data, err := os.ReadFile(filepath.Join(runDir, "report.json"))
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(data, &r)
	return r, err
}

func SafePathPart(value string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "..", "_")
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return "unknown"
	}
	return replacer.Replace(value)
}

func updateLatest(domainDir string, runID string) error {
	if err := os.MkdirAll(domainDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(domainDir, "latest.txt"), []byte(runID+"\n"), 0o644); err != nil {
		return err
	}
	latest := filepath.Join(domainDir, "latest")
	_ = os.RemoveAll(latest)
	_ = os.Symlink(runID, latest)
	return nil
}

func readRunInfo(domain string, runDir string, runID string) RunInfo {
	info := RunInfo{Domain: domain, ID: runID, Path: runDir}
	r, err := ReadReport(runDir)
	if err != nil {
		return info
	}
	info.Domain = r.Target.Domain
	info.GeneratedAt = r.GeneratedAt
	info.Score = r.Score.Overall
	info.Grade = r.Score.Grade
	info.Tools = append([]string(nil), r.Evidence.Tools.Selected...)
	return info
}
