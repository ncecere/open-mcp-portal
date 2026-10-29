package upstream

import (
	"context"
	"errors"
)

func (c *Client) protector() *Protection {
	c.protectionOnce.Do(func() {
		if c.Protection == nil {
			c.Protection = NewProtection()
		}
	})
	return c.Protection
}

// An admission callback is local control-plane code, not a remote OAuth
// rejection. Preserve its cause without returning internal messages/secrets.
func forwardAdmissionError(err error) error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return &Error{Class: ClassUnavailable, Message: "The outbound MCP attempt was not authorized.", cause: &BeforeTransportError{Err: err}}
}

func forwardCancellation(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		class, message := ClassTimeout, "The request deadline elapsed before contacting the server."
		if errors.Is(err, context.Canceled) {
			class, message = ClassUnavailable, "The request was cancelled before contacting the server."
		}
		return &Error{Class: class, Message: message, BeforeDispatch: true, cause: err}
	}
	return nil
}

func protectionResult(caller context.Context, err error) protectionOutcome {
	if caller.Err() != nil {
		return protectionNeutral
	}
	if err == nil {
		return protectionSuccess
	}
	var e *Error
	if !errors.As(err, &e) || e.cause != nil || e.Reason != "" {
		return protectionNeutral
	}
	switch e.Class {
	case ClassTLS, ClassTimeout, ClassBadResponse:
		return protectionFailure
	case ClassUnavailable:
		if e.HTTPStatus == 0 || e.HTTPStatus >= 500 {
			return protectionFailure
		}
	}
	if e.HTTPStatus != 0 {
		return protectionSuccess
	} // A responding auth/429 server is reachable.
	return protectionNeutral
}
