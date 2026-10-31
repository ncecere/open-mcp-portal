package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
)

// actor returns the authorization principal of a request: the person whose
// browser session it carries, or the automation token it authenticated with.
func (a *api) actor(r *http.Request) authz.Actor {
	if t, ok := authz.ActorFromContext(r.Context()); ok {
		return t // an automation token (tokenauth.go), with its request ID and address
	}
	reqID, ip := httpx.RequestID(r.Context()), httpx.ClientIP(r, a.Config.TrustedProxies)
	id, _ := auth.FromContext(r.Context())
	return id.Actor(reqID, ip)
}

// ifMatch reads the required If-Match revision. Missing → 428, malformed → 400.
func ifMatch(w http.ResponseWriter, r *http.Request) (int64, bool) {
	raw := strings.TrimSpace(r.Header.Get("If-Match"))
	if raw == "" {
		httpx.Error(w, http.StatusPreconditionRequired, "revision_required",
			"Send the If-Match header with the revision you loaded")
		return 0, false
	}
	raw = strings.TrimPrefix(raw, "W/")
	raw = strings.Trim(raw, `"`)
	rev, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || rev < 1 {
		httpx.Error(w, http.StatusBadRequest, "invalid_revision", "If-Match must be a revision such as \"3\"")
		return 0, false
	}
	return rev, true
}

func setETag(w http.ResponseWriter, revision int64) {
	w.Header().Set("ETag", `"`+strconv.FormatInt(revision, 10)+`"`)
}

func pathUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_id", "Invalid "+name)
		return uuid.Nil, false
	}
	return id, true
}

// pathEntryID reads a positive int64 audit entry ID.
func pathEntryID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("entryId"), 10, 64)
	if err != nil || id <= 0 {
		httpx.Error(w, http.StatusBadRequest, "invalid_id", "Invalid entryId")
		return 0, false
	}
	return id, true
}

const (
	defaultPageSize = 50
	maxPageSize     = 200
)

// pageLimit reads ?limit=. The query fetches one extra row to detect a
// following page.
func pageLimit(w http.ResponseWriter, r *http.Request) (int32, bool) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return defaultPageSize, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > maxPageSize {
		httpx.Error(w, http.StatusBadRequest, "invalid_limit", "limit must be between 1 and 200")
		return 0, false
	}
	return int32(n), true
}

// search reads ?q=, trimmed; empty means no filter.
func search(w http.ResponseWriter, r *http.Request) (*string, bool) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		return nil, true
	}
	if !utf8.ValidString(q) || strings.IndexByte(q, 0) >= 0 {
		httpx.Error(w, http.StatusBadRequest, "invalid_search", "Search text must be valid UTF-8 without NUL")
		return nil, false
	}
	if len(q) > 200 {
		httpx.Error(w, http.StatusBadRequest, "invalid_search", "Search text is too long")
		return nil, false
	}
	return &q, true
}

// Cursors are opaque to clients: base64url JSON of the last row's sort keys.
func encodeCursor(keys ...string) *string {
	b, _ := json.Marshal(keys)
	s := base64.RawURLEncoding.EncodeToString(b)
	return &s
}

func decodeCursor(w http.ResponseWriter, r *http.Request, n int) ([]string, bool) {
	raw := r.URL.Query().Get("cursor")
	if raw == "" {
		return nil, true
	}
	var keys []string
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || json.Unmarshal(b, &keys) != nil || len(keys) != n {
		httpx.Error(w, http.StatusBadRequest, "invalid_cursor", "Invalid cursor")
		return nil, false
	}
	return keys, true
}
