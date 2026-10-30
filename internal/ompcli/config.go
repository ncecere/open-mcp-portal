package ompcli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is what a command needs to reach the portal.
type Config struct {
	URL   string // the portal's base URL, no trailing slash
	Token string // an automation token; never printed
}

// fileConfig is ~/.config/omp/config.yaml.
type fileConfig struct {
	URL   string `yaml:"url,omitempty"`
	Token string `yaml:"token,omitempty"`
}

// tokenShape is an automation token: the prefix and 43 URL-safe characters
// (docs/automation-tokens.md). Anything else (an MCP key, an OAuth token) is
// refused here: /v1 would answer 401 and the secret would have crossed the
// network for nothing.
var tokenShape = regexp.MustCompile(`^(ompadm|omppub)_[A-Za-z0-9_-]{43}$`)

// ValidateToken checks the shape of an automation token without echoing it.
func ValidateToken(token string) error {
	if !tokenShape.MatchString(token) {
		return configErr("the token is not an automation token (ompadm_ or omppub_ followed by 43 characters); personal API keys and OAuth tokens are not accepted by /v1")
	}
	return nil
}

// ValidateURL checks a portal URL and returns it without a trailing slash.
// https is required; plain http is allowed only for a loopback host
// (localhost, 127.0.0.0/8, ::1), for local development. Credentials, a query
// and a fragment are refused, and the URL is not echoed back when it has
// credentials.
func ValidateURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", configErr("the portal URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", configErr("the portal URL is not a valid absolute URL (expected https://portal.example.com)")
	}
	if u.User != nil {
		return "", configErr("the portal URL must not contain a user name or password")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return "", configErr("the portal URL must not have a query or a fragment")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return "", configErr("refusing %s: plain http is only allowed for localhost and loopback addresses; use https", redactURL(u))
		}
	default:
		return "", configErr("the portal URL must start with https:// (http:// only for localhost)")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

func redactURL(u *url.URL) string {
	c := *u
	c.User = nil
	return c.String()
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// configPath is where the config file is: OMP_CONFIG, else
// $XDG_CONFIG_HOME/omp/config.yaml, else ~/.config/omp/config.yaml.
func (a *App) configPath() (string, error) {
	if p := a.Getenv("OMP_CONFIG"); p != "" {
		return p, nil
	}
	if x := a.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "omp", "config.yaml"), nil
	}
	home, err := a.HomeDir()
	if err != nil || home == "" {
		return "", configErr("cannot find your home directory; set OMP_URL and OMP_TOKEN instead")
	}
	return filepath.Join(home, ".config", "omp", "config.yaml"), nil
}

// readConfigFile reads the config file. A missing file is not an error. A file
// that group or others can read is refused (it holds a token), as ssh does for
// a private key. On Windows the mode bits don't describe access, so the check
// is skipped there.
func (a *App) readConfigFile(path string) (fileConfig, bool, error) {
	var fc fileConfig
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fc, false, nil
	}
	if err != nil {
		return fc, false, configErr("cannot read the config file %s: %v", path, err)
	}
	if !info.Mode().IsRegular() {
		return fc, false, configErr("the config file %s is not a regular file", path)
	}
	if a.goos() != "windows" && info.Mode().Perm()&0o077 != 0 {
		return fc, false, configErr("refusing to read %s: it is readable by other users (mode %04o); run: chmod 600 %s", path, info.Mode().Perm(), path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fc, false, configErr("cannot read the config file %s: %v", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&fc); err != nil && !errors.Is(err, io.EOF) {
		// Never include the decoder's excerpt of the file: it may hold the token.
		return fc, false, configErr("the config file %s is not valid (expected url: and token: keys)", path)
	}
	return fc, true, nil
}

// loadConfig resolves the URL and token: --portal, then OMP_URL, then the file;
// OMP_TOKEN, then the file. The file is read only when something is missing.
func (a *App) loadConfig(g *global, needToken bool) (*Config, error) {
	cfg := &Config{URL: strings.TrimSpace(g.url), Token: a.Getenv("OMP_TOKEN")}
	if cfg.URL == "" {
		cfg.URL = strings.TrimSpace(a.Getenv("OMP_URL"))
	}
	if cfg.URL == "" || (needToken && cfg.Token == "") {
		path, err := a.configPath()
		if err != nil {
			return nil, err
		}
		fc, _, err := a.readConfigFile(path)
		if err != nil {
			return nil, err
		}
		if cfg.URL == "" {
			cfg.URL = fc.URL
		}
		if cfg.Token == "" {
			cfg.Token = fc.Token
		}
	}
	if cfg.Token != "" {
		a.addSecret(cfg.Token)
	}
	if cfg.URL == "" {
		return nil, configErr("no portal URL: pass --portal, set OMP_URL, or run `omp configure --portal https://portal.example.com`")
	}
	u, err := ValidateURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	cfg.URL = u
	if needToken {
		if cfg.Token == "" {
			return nil, configErr("no token: set OMP_TOKEN, or store one with `omp configure --token-stdin`")
		}
		if err := ValidateToken(cfg.Token); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

// writeConfigFile writes the config file with mode 0600 in a directory of mode
// 0700 (created when missing), replacing it atomically.
func writeConfigFile(path string, fc fileConfig) error {
	raw, err := yaml.Marshal(fc)
	if err != nil {
		return err
	}
	return writePrivateFile(path, raw)
}

// writePrivateFile atomically replaces a file without exposing new sensitive
// configuration through an existing file's broader permissions.
func writePrivateFile(path string, raw []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".config-*.tmp") // created 0600
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
