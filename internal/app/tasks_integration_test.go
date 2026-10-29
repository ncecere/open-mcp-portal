package app_test

import (
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/app"
	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/mcpgw"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func taskConfig(t *testing.T) config.Config {
	t.Helper()
	cfg := config.Defaults()
	cfg.AppURL, cfg.DevAuth, cfg.DatabaseURL = "http://localhost:8088", true, "unused"
	cfg.EncryptionKey = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="
	cfg.APIKeyPepper = "cGVwcGVyLXBlcHBlci1wZXBwZXItcGVwcGVyLTAxMjM="
	return cfg
}

// The serving dependencies carry the task store with the configured bounds, and
// an invalid bound refuses to build them at all: never an absent (disabled) or
// unlimited store in its place.
func TestServingDependenciesRequireValidTaskLimits(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	cfg := taskConfig(t)
	deps, err := app.NewDeps(cfg, pool, testutil.Logger())
	if err != nil {
		t.Fatal(err)
	}
	if handler, ok := deps.MCP.(*mcpgw.Handler); !ok || handler.Tasks == nil {
		t.Fatalf("the gateway has no task store: %T", deps.MCP)
	}
	for name, mutate := range map[string]func(*config.Config){
		"zero lifetime":   func(c *config.Config) { c.TasksMaxTTL = 0 },
		"short lifetime":  func(c *config.Config) { c.TasksMaxTTL = time.Second },
		"long lifetime":   func(c *config.Config) { c.TasksMaxTTL = 48 * time.Hour },
		"zero open limit": func(c *config.Config) { c.TasksMaxOpenPerPrincipal = 0 },
		"huge open limit": func(c *config.Config) { c.TasksMaxOpenPerPrincipal = 5000 },
	} {
		bad := taskConfig(t)
		mutate(&bad)
		if d, err := app.NewDeps(bad, pool, testutil.Logger()); err == nil {
			t.Errorf("%s: dependencies built (tasks %v)", name, d.MCP != nil)
		}
		// The serve entry point refuses it before anything else runs.
		if err := bad.Validate("serve"); err == nil {
			t.Errorf("%s: validate accepted it", name)
		}
	}
}
