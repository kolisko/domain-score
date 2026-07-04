package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultAPIURL = "https://api.github.com/repos/kolisko/domain-score/releases/latest"
	BinaryName    = "domain-score"
)

type Config struct {
	CurrentVersion string
	APIURL         string
	ExecutablePath string
	GOOS           string
	GOARCH         string
	Client         *http.Client
}

type Release struct {
	TagName string  `json:"tag_name"`
	HTMLURL string  `json:"html_url"`
	Assets  []Asset `json:"assets"`
}

type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Digest             string `json:"digest"`
	Size               int64  `json:"size"`
}

type CheckResult struct {
	CurrentVersion string
	LatestVersion  string
	LatestURL      string
	Outdated       bool
}

func Check(ctx context.Context, config Config) (CheckResult, error) {
	config = withDefaults(config)
	release, err := Latest(ctx, config)
	if err != nil {
		return CheckResult{}, err
	}
	result := CheckResult{
		CurrentVersion: config.CurrentVersion,
		LatestVersion:  release.TagName,
		LatestURL:      release.HTMLURL,
	}
	result.Outdated = IsReleaseVersion(config.CurrentVersion) && CompareVersions(config.CurrentVersion, release.TagName) < 0
	return result, nil
}

func Latest(ctx context.Context, config Config) (Release, error) {
	config = withDefaults(config)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, config.APIURL, nil)
	if err != nil {
		return Release{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "domain-score-self-update")
	resp, err := config.Client.Do(req)
	if err != nil {
		return Release{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Release{}, fmt.Errorf("latest release returned HTTP %d", resp.StatusCode)
	}
	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return Release{}, err
	}
	if release.TagName == "" {
		return Release{}, errors.New("latest release did not contain tag_name")
	}
	return release, nil
}

func Update(ctx context.Context, config Config, out io.Writer) error {
	config = withDefaults(config)
	if out == nil {
		out = io.Discard
	}
	_, _ = fmt.Fprintf(out, "update: checking latest release %s\n", config.APIURL)
	release, err := Latest(ctx, config)
	if err != nil {
		return err
	}
	if IsReleaseVersion(config.CurrentVersion) && CompareVersions(config.CurrentVersion, release.TagName) >= 0 {
		_, _ = fmt.Fprintf(out, "domain-score is already up to date (%s)\n", config.CurrentVersion)
		return nil
	}
	assetName := AssetName(release.TagName, config.GOOS, config.GOARCH)
	asset, ok := findAsset(release.Assets, assetName)
	if !ok {
		return fmt.Errorf("latest release %s does not contain asset %s", release.TagName, assetName)
	}
	_, _ = fmt.Fprintf(out, "update: latest=%s current=%s asset=%s size=%s\n", release.TagName, config.CurrentVersion, asset.Name, formatBytes(asset.Size))
	exePath, err := executablePath(config.ExecutablePath)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "update: executable=%s\n", exePath)
	if err := cleanupStaleFiles(exePath); err != nil {
		return err
	}
	archivePath, err := downloadAsset(ctx, config, asset, exePath, out)
	if err != nil {
		return err
	}
	cleanupArchive := true
	defer func() {
		if cleanupArchive {
			_ = os.Remove(archivePath)
		}
	}()
	tmpBinaryPath := tempBinaryPath(exePath)
	_ = os.Remove(tmpBinaryPath)
	if err := extractBinary(archivePath, asset.Name, tmpBinaryPath, config.GOOS); err != nil {
		_ = os.Remove(tmpBinaryPath)
		return err
	}
	cleanupBinary := true
	defer func() {
		if cleanupBinary {
			_ = os.Remove(tmpBinaryPath)
		}
	}()
	mode := os.FileMode(0o755)
	if current, err := os.Stat(exePath); err == nil {
		mode = current.Mode() | 0o700
	}
	if err := os.Chmod(tmpBinaryPath, mode); err != nil {
		return err
	}
	if runtime.GOOS == "windows" || config.GOOS == "windows" {
		if err := scheduleWindowsReplace(tmpBinaryPath, exePath); err != nil {
			return err
		}
		cleanupBinary = false
		_, _ = fmt.Fprintf(out, "domain-score update to %s has been scheduled; run domain-score again after this process exits\n", release.TagName)
		return nil
	}
	_, _ = fmt.Fprintf(out, "update: replacing executable\n")
	if err := replaceExecutable(tmpBinaryPath, exePath); err != nil {
		return err
	}
	cleanupArchive = false
	cleanupBinary = false
	_ = os.Remove(archivePath)
	_, _ = fmt.Fprintf(out, "domain-score updated to %s\n", release.TagName)
	return nil
}

func IsReleaseVersion(version string) bool {
	version = strings.TrimSpace(version)
	return strings.HasPrefix(version, "v") && len(version) > 1 && version[1] >= '0' && version[1] <= '9'
}

func CompareVersions(a string, b string) int {
	ap := versionParts(a)
	bp := versionParts(b)
	maxLen := len(ap)
	if len(bp) > maxLen {
		maxLen = len(bp)
	}
	for i := 0; i < maxLen; i++ {
		var av, bv int
		if i < len(ap) {
			av = ap[i]
		}
		if i < len(bp) {
			bv = bp[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

func AssetName(version string, goos string, goarch string) string {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}
	return fmt.Sprintf("domain-score_%s_%s_%s%s", version, goos, goarch, ext)
}

func withDefaults(config Config) Config {
	if config.APIURL == "" {
		config.APIURL = DefaultAPIURL
	}
	if config.GOOS == "" {
		config.GOOS = runtime.GOOS
	}
	if config.GOARCH == "" {
		config.GOARCH = runtime.GOARCH
	}
	if config.Client == nil {
		config.Client = &http.Client{Timeout: 60 * time.Second}
	}
	if config.CurrentVersion == "" {
		config.CurrentVersion = "dev"
	}
	return config
}

func versionParts(version string) []int {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	version = strings.SplitN(version, "-", 2)[0]
	fields := strings.Split(version, ".")
	parts := make([]int, 0, len(fields))
	for _, field := range fields {
		value, err := strconv.Atoi(field)
		if err != nil {
			value = 0
		}
		parts = append(parts, value)
	}
	return parts
}

func findAsset(assets []Asset, name string) (Asset, bool) {
	for _, asset := range assets {
		if asset.Name == name {
			return asset, true
		}
	}
	return Asset{}, false
}

func executablePath(path string) (string, error) {
	if path == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", err
		}
		path = exe
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	return filepath.Abs(path)
}

func tempDownloadPath(exePath string) string {
	dir := filepath.Dir(exePath)
	base := filepath.Base(exePath)
	return filepath.Join(dir, fmt.Sprintf(".%s.update.%d.archive", base, os.Getpid()))
}

func tempBinaryPath(exePath string) string {
	dir := filepath.Dir(exePath)
	base := filepath.Base(exePath)
	return filepath.Join(dir, fmt.Sprintf(".%s.update.%d.tmp", base, os.Getpid()))
}

func tempScriptPath(exePath string) string {
	dir := filepath.Dir(exePath)
	base := filepath.Base(exePath)
	return filepath.Join(dir, fmt.Sprintf(".%s.update.%d.cmd", base, os.Getpid()))
}

func downloadAsset(ctx context.Context, config Config, asset Asset, exePath string, out io.Writer) (string, error) {
	if asset.BrowserDownloadURL == "" {
		return "", fmt.Errorf("asset %s does not contain browser_download_url", asset.Name)
	}
	tmpPath := tempDownloadPath(exePath)
	_ = os.Remove(tmpPath)
	_, _ = fmt.Fprintf(out, "update: downloading %s from %s\n", asset.Name, asset.BrowserDownloadURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.BrowserDownloadURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "domain-score-self-update")
	resp, err := config.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("download %s returned HTTP %d", asset.Name, resp.StatusCode)
	}
	file, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	total := asset.Size
	if total <= 0 && resp.ContentLength > 0 {
		total = resp.ContentLength
	}
	written, copyErr := copyWithProgress(io.MultiWriter(file, hash), resp.Body, out, asset.Name, total)
	closeErr := file.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return "", copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return "", closeErr
	}
	if asset.Size > 0 && written != asset.Size {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("downloaded %d bytes for %s, expected %d", written, asset.Name, asset.Size)
	}
	_, _ = fmt.Fprintf(out, "update: verifying sha256 for %s\n", asset.Name)
	if err := verifyDigest(asset, hash.Sum(nil)); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	return tmpPath, nil
}

func copyWithProgress(dst io.Writer, src io.Reader, out io.Writer, label string, total int64) (int64, error) {
	buffer := make([]byte, 256*1024)
	var written int64
	nextProgress := time.Now()
	for {
		n, readErr := src.Read(buffer)
		if n > 0 {
			if _, err := dst.Write(buffer[:n]); err != nil {
				return written, err
			}
			written += int64(n)
			now := time.Now()
			if !now.Before(nextProgress) {
				_, _ = fmt.Fprintf(out, "\rupdate: downloading %s %s%s", label, formatBytes(written), formatDownloadPercent(written, total))
				nextProgress = now.Add(250 * time.Millisecond)
			}
		}
		if readErr == io.EOF {
			_, _ = fmt.Fprintf(out, "\rupdate: downloaded %s %s%s\n", label, formatBytes(written), formatDownloadPercent(written, total))
			return written, nil
		}
		if readErr != nil {
			_, _ = fmt.Fprintln(out)
			return written, readErr
		}
	}
}

func extractBinary(archivePath string, assetName string, destPath string, goos string) error {
	if strings.HasSuffix(assetName, ".zip") || goos == "windows" {
		return extractZipBinary(archivePath, destPath)
	}
	return extractTarGzBinary(archivePath, destPath)
}

func extractTarGzBinary(archivePath string, destPath string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("%s not found in archive", BinaryName)
		}
		if err != nil {
			return err
		}
		if header.FileInfo().IsDir() || filepath.Base(header.Name) != BinaryName {
			continue
		}
		return writeExtracted(destPath, tr)
	}
}

func extractZipBinary(archivePath string, destPath string) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, file := range zr.File {
		name := strings.TrimSuffix(filepath.Base(file.Name), ".exe")
		if file.FileInfo().IsDir() || name != BinaryName {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return err
		}
		err = writeExtracted(destPath, rc)
		closeErr := rc.Close()
		if err != nil {
			return err
		}
		return closeErr
	}
	return fmt.Errorf("%s not found in archive", BinaryName)
}

func writeExtracted(destPath string, src io.Reader) error {
	file, err := os.OpenFile(destPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(file, src)
	closeErr := file.Close()
	if copyErr != nil {
		_ = os.Remove(destPath)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(destPath)
		return closeErr
	}
	return nil
}

func formatBytes(value int64) string {
	const unit = 1024
	if value <= 0 {
		return "unknown"
	}
	if value < unit {
		return fmt.Sprintf("%d B", value)
	}
	div := int64(unit)
	exp := 0
	for n := value / unit; n >= unit && exp < 4; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(value)/float64(div), "KMGTPE"[exp])
}

func formatDownloadPercent(done int64, total int64) string {
	if total <= 0 {
		return ""
	}
	percent := float64(done) * 100 / float64(total)
	if percent > 100 {
		percent = 100
	}
	return fmt.Sprintf(" / %s %.1f%%", formatBytes(total), percent)
}

func verifyDigest(asset Asset, got []byte) error {
	if asset.Digest == "" {
		return nil
	}
	want, ok := strings.CutPrefix(asset.Digest, "sha256:")
	if !ok {
		return nil
	}
	gotHex := hex.EncodeToString(got)
	if !strings.EqualFold(want, gotHex) {
		return fmt.Errorf("sha256 mismatch for %s", asset.Name)
	}
	return nil
}

func replaceExecutable(tmpPath string, exePath string) error {
	if err := os.Rename(tmpPath, exePath); err != nil {
		return fmt.Errorf("replace executable: %w", err)
	}
	return nil
}

func scheduleWindowsReplace(tmpPath string, exePath string) error {
	scriptPath := tempScriptPath(exePath)
	_ = os.Remove(scriptPath)
	script := fmt.Sprintf(`@echo off
setlocal
:wait
tasklist /FI "PID eq %d" 2>NUL | find "%d" >NUL
if not errorlevel 1 (
  timeout /T 1 /NOBREAK >NUL
  goto wait
)
move /Y %s %s >NUL
if errorlevel 1 (
  del %s >NUL 2>NUL
  del "%%~f0" >NUL 2>NUL
  exit /B 1
)
del "%%~f0" >NUL 2>NUL
`, os.Getpid(), os.Getpid(), quoteWindows(tmpPath), quoteWindows(exePath), quoteWindows(tmpPath))
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		return err
	}
	cmd := exec.Command("cmd", "/C", scriptPath)
	if err := cmd.Start(); err != nil {
		_ = os.Remove(scriptPath)
		return err
	}
	return nil
}

func quoteWindows(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func cleanupStaleFiles(exePath string) error {
	dir := filepath.Dir(exePath)
	base := filepath.Base(exePath)
	patterns := []string{
		filepath.Join(dir, "."+base+".update.*.archive"),
		filepath.Join(dir, "."+base+".update.*.tmp"),
		filepath.Join(dir, "."+base+".update.*.cmd"),
	}
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return err
		}
		for _, match := range matches {
			_ = os.Remove(match)
		}
	}
	return nil
}
