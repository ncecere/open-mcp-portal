package approvals

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestConcurrentNewUsesWinningBindingRoot(t *testing.T) {
	db, _ := testutil.NewDB(t)
	before, err := dbgen.New(db).GetApprovalContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	box, err := secrets.New(bytes.Repeat([]byte{0x61}, 32))
	if err != nil {
		t.Fatal(err)
	}
	const n = 12
	services := make(chan *Service, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			s, err := New(db, box, nil, "https://portal.test")
			if err != nil {
				errs <- err
				return
			}
			services <- s
		})
	}
	wg.Wait()
	close(services)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var cipher []byte
	if err := db.QueryRow(context.Background(), `SELECT binding_key_cipher FROM omp_private.approval_binding_keys WHERE id=1`).Scan(&cipher); err != nil {
		t.Fatal(err)
	}
	root, err := box.Open(cipher, BindingKeyAAD())
	if err != nil || len(root) != 32 {
		t.Fatal("invalid stored root", err)
	}
	for s := range services {
		if len(s.keys) != 1 || !bytes.Equal(s.keys[0], root) {
			t.Fatal("constructor cached a losing or derived root")
		}
	}
	other, _ := box.Seal(bytes.Repeat([]byte{0x62}, 32), BindingKeyAAD())
	stored, err := dbgen.New(db).EnsureApprovalBindingKey(context.Background(), other)
	if err != nil || !bytes.Equal(stored, cipher) {
		t.Fatal("ensure overwrote the winning root", err)
	}
	if _, err := box.Open(cipher, []byte("approval_binding_key:v2")); err == nil {
		t.Fatal("root is not AAD-bound")
	}
	if after, err := dbgen.New(db).GetApprovalContext(context.Background()); err != nil || after != before {
		t.Fatal("root bootstrap changed semantic context", err)
	}
}

func TestNewFailsClosedOnInvalidStoredBindingRoot(t *testing.T) {
	for _, kind := range []string{"wrong AAD", "short root", "long root", "unknown key", "malformed", "tampered"} {
		t.Run(kind, func(t *testing.T) {
			db, _ := testutil.NewDB(t)
			b, _ := secrets.New(bytes.Repeat([]byte{0x61}, 32))
			plain, aad := bytes.Repeat([]byte{0x42}, 32), BindingKeyAAD()
			sealing := b
			switch kind {
			case "wrong AAD":
				aad = []byte("wrong")
			case "short root":
				plain = plain[:31]
			case "long root":
				plain = append(plain, 0)
			case "unknown key":
				sealing, _ = secrets.New(bytes.Repeat([]byte{0x63}, 32))
			}
			cipher, err := sealing.Seal(plain, aad)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "malformed" {
				cipher = bytes.Repeat([]byte{0}, 69)
			} else if kind == "tampered" {
				cipher[len(cipher)-1] ^= 1
			}
			stored, err := dbgen.New(db).EnsureApprovalBindingKey(context.Background(), cipher)
			if err != nil || !bytes.Equal(stored, cipher) {
				t.Fatal(err)
			}
			s, err := New(db, b, nil, "https://portal.test")
			if s != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("invalid root did not fail closed: %v", err)
			}
			var after []byte
			if err := db.QueryRow(context.Background(), `SELECT binding_key_cipher FROM omp_private.approval_binding_keys WHERE id=1`).Scan(&after); err != nil || !bytes.Equal(after, cipher) {
				t.Fatal("invalid root was replaced", err)
			}
		})
	}
}
