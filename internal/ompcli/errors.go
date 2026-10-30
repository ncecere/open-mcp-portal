package ompcli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// Exit codes. They are part of the CLI's contract (docs/cli.md) and stay
// stable: a script may branch on them.
const (
	ExitOK          = 0  // success
	ExitFailure     = 1  // an unexpected internal error
	ExitUsage       = 2  // bad flags, arguments or declarative file
	ExitConfig      = 3  // no URL or token, an unsafe URL, or an unsafe config file
	ExitAuth        = 4  // 401: the token is missing, unknown, expired or revoked
	ExitForbidden   = 5  // 403: the token may not do this (details name the scope)
	ExitNotFound    = 6  // 404
	ExitConflict    = 7  // 409, 412, 428: the object changed, or is in the wrong state
	ExitRejected    = 8  // 400, 422 and other 4xx: the API refused the request
	ExitUnavailable = 9  // 5xx, 429, or the portal could not be reached
	ExitChanges     = 10 // changes found: `import --plan` drift, `servers refresh --fail-on-changes`
	ExitCheckFailed = 11 // a check ran and failed: `servers test` ok=false, discovery failed
)

// Error is a failure with an exit code and, for API errors, the API's
// error.code (docs/cli.md: every error carries one).
type Error struct {
	Exit    int
	Code    string // the API's error.code, or the CLI's own (usage, config, network, ...)
	Message string
	Status  int            // HTTP status, 0 when there was none
	Details map[string]any // the API's error.details
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func usageErr(format string, args ...any) *Error {
	return &Error{Exit: ExitUsage, Code: "usage", Message: fmt.Sprintf(format, args...)}
}

func configErr(format string, args ...any) *Error {
	return &Error{Exit: ExitConfig, Code: "config", Message: fmt.Sprintf(format, args...)}
}

func networkErr(err error) *Error {
	return &Error{Exit: ExitUnavailable, Code: "network", Message: "the portal could not be reached: " + err.Error()}
}

// exitFor maps an HTTP status and API error code to an exit code.
func exitFor(status int, code string) int {
	switch {
	case code == "discovery_failed":
		return ExitCheckFailed
	case status == http.StatusUnauthorized:
		return ExitAuth
	case status == http.StatusForbidden:
		return ExitForbidden
	case status == http.StatusNotFound:
		return ExitNotFound
	case status == http.StatusConflict, status == http.StatusPreconditionFailed, status == http.StatusPreconditionRequired:
		return ExitConflict
	case status == http.StatusTooManyRequests, status >= 500:
		return ExitUnavailable
	case status >= 400:
		return ExitRejected
	}
	return ExitFailure
}

// apiError builds the error for a non-success response, from the API's
// {"error": {"code", "message", "details"}} body when it has one.
func apiError(status int, body []byte) *Error {
	var env struct {
		Error struct {
			Code    string         `json:"code"`
			Message string         `json:"message"`
			Details map[string]any `json:"details"`
		} `json:"error"`
	}
	e := &Error{Status: status}
	if json.Unmarshal(body, &env) == nil && env.Error.Code != "" {
		e.Code, e.Message, e.Details = env.Error.Code, env.Error.Message, env.Error.Details
	} else {
		e.Code = "http_" + fmt.Sprint(status)
		e.Message = http.StatusText(status)
		if status >= 300 && status < 400 {
			e.Code, e.Message = "unexpected_redirect", "the portal answered with a redirect; check the URL (redirects are never followed)"
		} else if e.Message == "" {
			e.Message = "unexpected response"
		}
	}
	e.Exit = exitFor(status, e.Code)
	return e
}

// asError returns err as an *Error, wrapping anything else as a failure.
func asError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return &Error{Exit: ExitFailure, Code: "internal", Message: err.Error()}
}

type statusBody interface {
	StatusCode() int
	GetBody() []byte
}

// check turns a transport error or a non-2xx response into an *Error.
func check[R statusBody](res R, err error) (R, error) {
	if err != nil {
		return res, networkErr(err)
	}
	if res.StatusCode() < 200 || res.StatusCode() > 299 {
		return res, apiError(res.StatusCode(), res.GetBody())
	}
	return res, nil
}
