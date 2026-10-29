package store

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// EndpointReader is the limited database capability needed by provider HTTP
// exchanges. It deliberately exposes neither a transaction nor general SQL.
type EndpointReader interface {
	GetNetworkSettings(context.Context) (dbgen.NetworkSetting, error)
	GetAuthProvider(context.Context, uuid.UUID) (dbgen.AuthProvider, error)
}

type endpointReadsKey struct{}

var ErrEndpointReadsClosed = errors.New("store: endpoint reads closed")

// EndpointReadScope serializes reads on a transaction, including transport dials
// whose contexts have been detached from the request's cancellation.
type EndpointReadScope struct {
	reader EndpointReader
	ctx    context.Context
	cancel context.CancelFunc
	closed atomic.Bool
	mu     sync.Mutex
	err    error
}

// WithEndpointReads must be called after setting the exchange deadline and
// before HTTP can detach a dial context. Close must finish before the caller
// resumes any other transaction SQL (not merely before the transaction ends).
func WithEndpointReads(ctx context.Context, q EndpointReader) (context.Context, *EndpointReadScope) {
	owned, cancel := context.WithCancel(ctx)
	s := &EndpointReadScope{reader: q, ctx: owned, cancel: cancel}
	return context.WithValue(owned, endpointReadsKey{}, s), s
}

// EndpointReads returns a capability even after it has closed: callers must not
// fall back to the pool when an exchange's lifetime has ended.
func EndpointReads(ctx context.Context) (EndpointReader, bool) {
	s, ok := ctx.Value(endpointReadsKey{}).(*EndpointReadScope)
	return s, ok
}

// Close first rejects future/queued reads and cancels active SQL, then drains it.
// On return no scope read can still be using the transaction.
func (s *EndpointReadScope) Close() {
	s.closed.Store(true)
	s.cancel()
	s.mu.Lock()
	s.mu.Unlock()
}

// Err returns the first failed SQL read, including failures from asynchronous
// dials. Inspect it after Close and abort the transaction when non-nil.
func (s *EndpointReadScope) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// begin holds mu until the SQL completes. Both the scope's original deadline
// and the individual caller can cancel SQL; WithoutCancel cannot remove the
// scope's lifetime. Recheck closure after waiting for another read.
func (s *EndpointReadScope) begin(ctx context.Context) (context.Context, func(), error) {
	if s.closed.Load() {
		return nil, nil, ErrEndpointReadsClosed
	}
	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		return nil, nil, ErrEndpointReadsClosed
	}
	qctx, cancel := context.WithCancel(s.ctx)
	stop := context.AfterFunc(ctx, cancel)
	if err := ctx.Err(); err != nil {
		cancel()
	}
	if err := qctx.Err(); err != nil {
		stop()
		cancel()
		if s.err == nil {
			s.err = err
		}
		s.mu.Unlock()
		return nil, nil, err
	}
	return qctx, func() { stop(); cancel(); s.mu.Unlock() }, nil
}

func (s *EndpointReadScope) GetNetworkSettings(ctx context.Context) (dbgen.NetworkSetting, error) {
	qctx, done, err := s.begin(ctx)
	if err != nil {
		return dbgen.NetworkSetting{}, err
	}
	defer done()
	row, err := s.reader.GetNetworkSettings(qctx)
	if err != nil && s.err == nil {
		s.err = err
	}
	return row, err
}

func (s *EndpointReadScope) GetAuthProvider(ctx context.Context, id uuid.UUID) (dbgen.AuthProvider, error) {
	qctx, done, err := s.begin(ctx)
	if err != nil {
		return dbgen.AuthProvider{}, err
	}
	defer done()
	row, err := s.reader.GetAuthProvider(qctx, id)
	if err != nil && s.err == nil {
		s.err = err
	}
	return row, err
}
