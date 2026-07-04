package tools

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDockerRunArgs(t *testing.T) {
	got := DockerRunArgs("image:test", "/tmp/cache", "example.com", "https://example.com", []string{"subfinder", "httpx"})
	want := []string{
		"run",
		"--rm",
		"--read-only",
		"--tmpfs", "/tmp",
		"--network", "bridge",
		"-e", "HOME=/tmp",
		"-v", "/tmp/cache:/work:rw",
		"image:test",
		"scan",
		"--domain", "example.com",
		"--url", "https://example.com",
		"--tools", "subfinder,httpx",
		"--out", "/work",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DockerRunArgs = %#v, want %#v", got, want)
	}
}

func TestPrepareCacheDirReplacesLatest(t *testing.T) {
	base := t.TempDir()
	first, err := prepareCacheDir(base, "Example.COM")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(first, "old.txt"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := prepareCacheDir(base, "Example.COM")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("cache dir changed: %q != %q", first, second)
	}
	if _, err := os.Stat(filepath.Join(second, "old.txt")); !os.IsNotExist(err) {
		t.Fatalf("old cache file still exists or unexpected error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(second, "raw")); err != nil {
		t.Fatalf("raw cache dir missing: %v", err)
	}
}
