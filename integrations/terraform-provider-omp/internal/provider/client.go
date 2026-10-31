package provider

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/pkg/ompclient"
)

var (
	malformed    = errors.New("Portal metadata is missing, malformed or inconsistent. Upgrade the portal/provider and check the selected team.")
	notFound     = errors.New("Metadata not found. Check the team and slug/ID and the token's exact team.")
	keyPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,127}$`)
	tokenPattern = regexp.MustCompile(`^(omppub|ompadm)_[A-Za-z0-9_-]{43}$`)
)

type reader struct {
	client *ompclient.Client
	kind   string
	token  string
}

func newReader(base, token string) (*reader, error) {
	u, err := url.Parse(base)
	if err != nil || u == nil || u.Host == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(base, "#") || u.RawPath != "" {
		return nil, errors.New("Set a portal URL without credentials, query, fragment or encoded path.")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if u.Scheme != "https" && !(u.Scheme == "http" && (host == "localhost" || ip != nil && ip.IsLoopback())) {
		return nil, errors.New("Use HTTPS with a trusted certificate; HTTP is allowed only for localhost or a loopback IP.")
	}
	if !tokenPattern.MatchString(token) {
		return nil, errors.New("Set the selected token environment variable to an existing automation token (omppub_ or ompadm_).")
	}
	// An isolated transport has no cookie jar, custom auth, insecure TLS or logging.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSHandshakeTimeout = 10 * time.Second
	httpClient := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	client, err := ompclient.NewClient(strings.TrimRight(base, "/"), ompclient.WithHTTPClient(httpClient), ompclient.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
		if req.Method != http.MethodGet || req.URL.Scheme != u.Scheme || req.URL.Host != u.Host || req.URL.User != nil {
			return errors.New("request refused")
		}
		req.Header.Set("Authorization", "Bearer "+token)
		return nil
	}))
	if err != nil {
		return nil, errors.New("Set a valid portal base URL.")
	}
	kind := "team_publisher"
	if strings.HasPrefix(token, "ompadm_") {
		kind = "platform_admin"
	}
	return &reader{client: client, kind: kind, token: token}, nil
}

func (r *reader) decode(resp *http.Response, err error, out any) error {
	if err != nil {
		return errors.New("Portal read failed or timed out. Check connectivity, trusted TLS certificates and the request deadline.")
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 200:
	case 401:
		return errors.New("Automation token is invalid, expired or revoked. Supply an active token through the selected environment variable.")
	case 403:
		return errors.New("Token kind or scope is not permitted. Server reads require an exact-team publisher with servers:read; team reads require a platform token with platform:read.")
	case 404:
		return notFound
	default:
		return errors.New("Portal returned an unsupported status (including redirects or rate limits). Check portal availability; redirects are never followed.")
	}
	// Never retain/log arbitrary upstream bodies in diagnostics or state.
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024+1))
	if err != nil || len(b) > 4*1024*1024 || strings.Contains(string(b), r.token) {
		return malformed
	}
	if json.Unmarshal(b, out) != nil {
		return malformed
	}
	return nil
}

func validKey(s string) bool { return keyPattern.MatchString(s) || validID(s) }
func validID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id != uuid.Nil && id.String() == s
}

// Pointer fields distinguish absent/null from valid zero/false values.
type serverMeta struct {
	ID       *string `json:"id"`
	Slug     *string `json:"slug"`
	TeamID   *string `json:"teamId"`
	TeamSlug *string `json:"teamSlug"`
	Name     *string `json:"name"`
	Enabled  *bool   `json:"enabled"`
	Revision *int64  `json:"revision"`
	Counts   *struct {
		Tools     *int64 `json:"tools"`
		Prompts   *int64 `json:"prompts"`
		Resources *int64 `json:"resources"`
		Templates *int64 `json:"resourceTemplates"`
	} `json:"counts"`
	SupportsTasks *bool `json:"supportsTasks"`
}

func (s serverMeta) valid(team string) bool {
	if s.ID == nil || !validID(*s.ID) || s.TeamID == nil || !validID(*s.TeamID) || s.Slug == nil || !keyPattern.MatchString(*s.Slug) || s.TeamSlug == nil || !keyPattern.MatchString(*s.TeamSlug) || s.Name == nil || s.Enabled == nil || s.Revision == nil || *s.Revision < 1 || s.Counts == nil {
		return false
	}
	c := s.Counts
	return (team == *s.TeamID || team == *s.TeamSlug) && c.Tools != nil && *c.Tools >= 0 && c.Prompts != nil && *c.Prompts >= 0 && c.Resources != nil && *c.Resources >= 0 && c.Templates != nil && *c.Templates >= 0
}

type serverReply struct {
	Data *serverMeta `json:"data"`
}

func (r *reader) server(ctx context.Context, team, key string) (*serverMeta, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if r.kind != "team_publisher" {
		return nil, errors.New("Server metadata requires an exact-team publisher token with servers:read, not a platform token.")
	}
	if !validKey(team) || !validKey(key) {
		return nil, errors.New("Use a team slug/UUID and server slug/canonical UUID.")
	}
	id := key
	if !validID(key) {
		cursor := ""
		seen := map[string]bool{}
		id = ""
		for page := 0; page < 100; page++ {
			params := &ompclient.ListTeamMcpServersParams{}
			if cursor != "" {
				params.Cursor = &cursor
			}
			var reply struct {
				Data *struct {
					Items *[]serverMeta `json:"items"`
					Next  *string       `json:"nextCursor"`
				} `json:"data"`
			}
			resp, err := r.client.ListTeamMcpServers(ctx, team, params)
			if err = r.decode(resp, err, &reply); err != nil {
				return nil, err
			}
			if reply.Data == nil || reply.Data.Items == nil {
				return nil, malformed
			}
			for _, s := range *reply.Data.Items {
				if !s.valid(team) {
					return nil, malformed
				}
				if *s.Slug == key {
					if id != "" {
						return nil, malformed
					}
					id = *s.ID
				}
			}
			if reply.Data.Next == nil {
				break
			}
			cursor = *reply.Data.Next
			if cursor == "" || seen[cursor] || page == 99 {
				return nil, malformed
			}
			seen[cursor] = true
		}
		if id == "" {
			return nil, notFound
		}
	}
	parsed, _ := uuid.Parse(id)
	var reply serverReply
	resp, err := r.client.GetTeamMcpServer(ctx, team, parsed)
	if err = r.decode(resp, err, &reply); err != nil {
		return nil, err
	}
	if reply.Data == nil || !reply.Data.valid(team) || *reply.Data.ID != id || (!validID(key) && *reply.Data.Slug != key) {
		return nil, malformed
	}
	return reply.Data, nil
}

type teamMeta struct {
	ID       *string `json:"id"`
	Slug     *string `json:"slug"`
	Name     *string `json:"name"`
	Status   *string `json:"status"`
	Revision *int64  `json:"revision"`
}

func (r *reader) team(ctx context.Context, key string) (*teamMeta, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if r.kind != "platform_admin" {
		return nil, errors.New("Team metadata requires a platform token with platform:read; publisher tokens cannot call the session-only team route.")
	}
	if !validKey(key) {
		return nil, errors.New("Use a team slug or canonical UUID.")
	}
	var reply struct {
		Data *struct {
			Team *teamMeta `json:"team"`
		} `json:"data"`
	}
	resp, err := r.client.AdminGetTeam(ctx, key)
	if err = r.decode(resp, err, &reply); err != nil {
		return nil, err
	}
	if reply.Data == nil || reply.Data.Team == nil {
		return nil, malformed
	}
	t := reply.Data.Team
	if t.ID == nil || !validID(*t.ID) || t.Slug == nil || !keyPattern.MatchString(*t.Slug) || (key != *t.ID && key != *t.Slug) || t.Name == nil || t.Status == nil || (*t.Status != "active" && *t.Status != "archived") || t.Revision == nil || *t.Revision < 1 {
		return nil, malformed
	}
	return t, nil
}
