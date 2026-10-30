package ompcli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExportDashIsStdoutAndNeverCreatesDashFile(t *testing.T) {
	t.Chdir(t.TempDir())
	f := newFakePortal(t)
	h := newHarness(t)
	h.connect(f, f.publisher("bravo"))
	code, out, errOut := h.run("export", "-o", "-")
	if code != 0 || !strings.Contains(out, "schema: omp/v1") {
		t.Fatalf("stdout export: %d %q %q", code, out, errOut)
	}
	if _, err := os.Lstat("-"); !os.IsNotExist(err) {
		t.Fatalf("dash output created a file: %v", err)
	}
}

func TestExportRefusesToReplaceSymlinksAndDirectories(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires additional Windows privileges")
	}
	f := newFakePortal(t)
	h := newHarness(t)
	h.connect(f, f.publisher("bravo"))
	dir := t.TempDir()
	target, link := filepath.Join(dir, "target"), filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, dir} {
		if code, _, errOut := h.run("export", "-o", path); code != ExitFailure || !strings.Contains(errOut, "regular file") {
			t.Fatalf("non-regular output: %d %s", code, errOut)
		}
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink replaced: %v %v", info, err)
	}
	if raw, err := os.ReadFile(target); err != nil || string(raw) != "unchanged" {
		t.Fatalf("target changed: %q %v", raw, err)
	}
}

func TestPrivateExportReplacesBroaderPermissionsAtomically(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits do not express Windows ACLs")
	}
	path := filepath.Join(t.TempDir(), "export.yaml")
	if err := os.WriteFile(path, []byte("old content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFile(path, []byte("private policy")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("replacement mode: %v %v", info, err)
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "private policy" {
		t.Fatalf("replacement contents: %q %v", contents, err)
	}
	files, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(files) != 1 {
		t.Fatalf("temporary files left behind: %v %v", files, err)
	}
}
