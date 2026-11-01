// Package apperr defines errors that carry an HTTP status, a stable machine
// code and a user-safe message. Domain services return them; the HTTP layer
// renders them as {"error": {"code", "message"}}. Any other error is a 500.
package apperr

import (
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

type Error struct {
	Status  int
	Code    string
	Message string
	// Details, when set, is rendered as error.details (structured context
	// such as {limit, max, current} for limit_reached).
	Details any
	// RetryAfter, when positive, is sent as the Retry-After header (429, 503).
	RetryAfter time.Duration
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func New(status int, code, message string) *Error {
	return &Error{Status: status, Code: code, Message: message}
}

func Invalid(code, message string) *Error { return New(http.StatusBadRequest, code, message) }

func Forbidden(message string) *Error { return New(http.StatusForbidden, "forbidden", message) }

func NotFound(code, message string) *Error { return New(http.StatusNotFound, code, message) }

func Conflict(code, message string) *Error { return New(http.StatusConflict, code, message) }

// Stale is returned when an If-Match revision no longer matches.
func Stale() *Error {
	return New(http.StatusPreconditionFailed, "revision_conflict",
		"Someone else changed this since you loaded it. Reload and try again.")
}

// As returns the *Error in err's chain, if any.
func As(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}

// Postgres error codes we map to user-facing errors.
const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
	// pgRestrictViolation is what PostgreSQL 18 reports for a delete that ON DELETE RESTRICT blocks; up to 17 it was
	// 23503 as for any other foreign key.
	pgRestrictViolation = "23001"
)

// IsUniqueViolation reports whether err is a unique violation on constraint
// (any constraint if constraint is "").
func IsUniqueViolation(err error, constraint string) bool {
	return isPG(err, pgUniqueViolation, constraint)
}

// IsForeignKeyViolation reports whether err is a foreign-key violation: a row refers to what was deleted (or what was
// inserted refers to nothing), including PostgreSQL 18's restrict_violation for ON DELETE RESTRICT.
func IsForeignKeyViolation(err error, constraint string) bool {
	return isPG(err, pgForeignKeyViolation, constraint) || isPG(err, pgRestrictViolation, constraint)
}

// DirectoryGuard maps the database's directory-provisioning guards (decision
// 92) to a 409, so every writer that trips one answers the same way.
func DirectoryGuard(err error) (*Error, bool) {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "23514" {
		return nil, false
	}
	switch pg.ConstraintName {
	case "users_directory_protected_admin":
		return Conflict("protected_principal", "Directory-managed people can't be platform admins. Unlink them from provisioning first."), true
	case "users_directory_protected_owner", "team_members_directory_protected_owner":
		return Conflict("protected_principal", "Directory-managed people can't be team owners. Unlink them from provisioning first."), true
	case "users_directory_cleanup_pending":
		return Conflict("cleanup_pending", "This person's deprovisioning clean-up hasn't finished yet"), true
	}
	return nil, false
}

func isPG(err error, code, constraint string) bool {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != code {
		return false
	}
	return constraint == "" || pg.ConstraintName == constraint
}
