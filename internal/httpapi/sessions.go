package httpapi

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func (a *api) sessionRoutes() []route {
	return []route{
		{"GET", "/v1/me/sessions", a.session(a.listMySessions)},
		{"DELETE", "/v1/me/sessions/{sessionId}", a.session(a.revokeMySession)},
		{"POST", "/v1/me/sessions/revoke-all", a.session(a.signOutEverywhere)},
		{"GET", "/v1/admin/users/{userId}/sessions", a.admin(a.adminListUserSessions)},
		{"DELETE", "/v1/admin/users/{userId}/sessions", a.admin(a.adminRevokeUserSessions)},
	}
}

func (a *api) listSessions(w http.ResponseWriter, r *http.Request, userID uuid.UUID, admin bool) {
	id, _ := auth.FromContext(r.Context())
	rows, err := a.Auth.ListSessions(r.Context(), a.actor(r), userID, admin)
	writeList(w, r, rows, err, func(row dbgen.ListUserSessionsRow) apitypes.BrowserSession {
		return apitypes.BrowserSession{Id: row.ID, CreatedAt: row.CreatedAt, LastSeenAt: row.LastSeenAt,
			ExpiresAt: row.ExpiresAt, UserAgent: row.UserAgent, ClientIp: row.ClientIP, Current: row.ID.String() == id.SessionID}
	})
}

func (a *api) listMySessions(w http.ResponseWriter, r *http.Request) {
	a.listSessions(w, r, a.actor(r).UserID, false)
}

func (a *api) revokeMySession(w http.ResponseWriter, r *http.Request) {
	sessionID, ok := pathUUID(w, r, "sessionId")
	if !ok {
		return
	}
	err := a.Auth.RevokeSessions(r.Context(), a.actor(r), a.actor(r).UserID, &sessionID, nil, false)
	if err == nil {
		id, _ := auth.FromContext(r.Context())
		if sessionID.String() == id.SessionID {
			a.Auth.ClearSessionCookie(w)
		}
	}
	writeOK(w, r, err)
}

func (a *api) signOutEverywhere(w http.ResponseWriter, r *http.Request) {
	var in apitypes.RevokeSessionsInput
	// The contract permits an absent body. A supplied body is strictly decoded.
	if r.Body != nil && r.ContentLength != 0 {
		if !httpx.Decode(w, r, &in) {
			return
		}
	}
	var keep *uuid.UUID
	if in.KeepCurrent != nil && *in.KeepCurrent {
		id, _ := auth.FromContext(r.Context())
		current := uuid.MustParse(id.SessionID)
		keep = &current
	}
	err := a.Auth.RevokeSessions(r.Context(), a.actor(r), a.actor(r).UserID, nil, keep, false)
	if err == nil && keep == nil {
		a.Auth.ClearSessionCookie(w)
	}
	writeOK(w, r, err)
}

func (a *api) adminListUserSessions(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "userId")
	if !ok {
		return
	}
	a.listSessions(w, r, id, true)
}

func (a *api) adminRevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "userId")
	if !ok {
		return
	}
	err := a.Auth.RevokeSessions(r.Context(), a.actor(r), id, nil, nil, true)
	if err == nil && id == a.actor(r).UserID {
		a.Auth.ClearSessionCookie(w)
	}
	writeOK(w, r, err)
}
