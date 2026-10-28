package httpapi_test

import (
	"io/fs"
	"testing"
	"testing/fstest"
)

// singleMigrationFS exposes one complete embedded migration to Goose, which
// remains responsible for parsing and executing its Up and Down sections.
func singleMigrationFS(t *testing.T, source fs.FS, name string) fs.FS {
	t.Helper()
	data, err := fs.ReadFile(source, name)
	if err != nil {
		t.Fatal(err)
	}
	return fstest.MapFS{name: &fstest.MapFile{Data: data, Mode: 0444}}
}
