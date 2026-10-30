package ompcli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

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
