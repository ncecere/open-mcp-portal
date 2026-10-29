package upstream

import (
	"sync"
	"time"
)

// Protection bounds in-flight forwards and remembers circuit state per replica.
// Its key is a registered server ID, never a caller/credential or arbitrary URL.
// It holds no authority/database lock and never queues callers.
type Protection struct {
	mu      sync.Mutex
	entries map[string]*serverProtection
	now     func() time.Time
	max     int
}

type serverProtection struct {
	active, failures int
	generation       uint64
	openedUntil      time.Time
	probing          bool
	touched          time.Time
}

const (
	CircuitFailureThreshold = 5
	CircuitOpenDuration     = 30 * time.Second
	MaxProtectionServers    = 4096
	MaxServerConcurrency    = 10_000
)

// NewProtection returns a replica-local controller. The bounded cache never
// evicts active leases, half-open probes or a circuit still in its open period.
func NewProtection() *Protection {
	return newProtection(time.Now, MaxProtectionServers)
}

func newProtection(now func() time.Time, maxEntries int) *Protection {
	return &Protection{entries: make(map[string]*serverProtection), now: now, max: maxEntries}
}

type protectionOutcome uint8

const (
	protectionNeutral protectionOutcome = iota
	protectionSuccess
	protectionFailure
)

type protectionLease struct {
	owner      *Protection
	state      *serverProtection
	generation uint64
	probe      bool
	once       sync.Once
}

// acquire reserves a whole forwarded operation (including retries/cleanup).
// Zero cap is unlimited; negative/corrupt caps fail closed. An empty ID is an
// unregistered low-level target and receives no portal server policy.
func (p *Protection) acquire(id string, cap int32) (*protectionLease, *Error) {
	if cap < 0 || cap > MaxServerConcurrency {
		return nil, &Error{Class: ClassConfig, Message: "The server's concurrency setting is invalid."}
	}
	if id == "" {
		return &protectionLease{}, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	s := p.entries[id]
	if s == nil {
		if len(p.entries) >= p.max && !p.evict(now) {
			return nil, serverBusy()
		}
		s = &serverProtection{}
		p.entries[id] = s
	}
	s.touched = now
	if now.Before(s.openedUntil) || s.probing {
		delay := max(s.openedUntil.Sub(now), time.Second)
		return nil, circuitOpen(delay)
	}
	if cap > 0 && s.active >= int(cap) {
		return nil, serverBusy()
	}
	probe := !s.openedUntil.IsZero()
	if probe {
		s.probing = true
	}
	s.active++
	return &protectionLease{owner: p, state: s, generation: s.generation, probe: probe}, nil
}

func serverBusy() *Error {
	return &Error{Class: ClassServerBusy, HTTPStatus: 429, Reason: "server_busy", RetryAfter: time.Second,
		Message: "The server is at its concurrent-operation limit; try again shortly."}
}

func circuitOpen(delay time.Duration) *Error {
	return &Error{Class: ClassCircuitOpen, Reason: "circuit_open", RetryAfter: delay,
		Message: "The server's circuit is open while it recovers; try again shortly."}
}

// evict is called under mu and removes at most one idle entry. If every
// entry is protected, refuse a new admission instead of bypassing a live cap.
func (p *Protection) evict(now time.Time) bool {
	var key string
	var oldest time.Time
	for k, s := range p.entries {
		if s.active > 0 || s.probing || now.Before(s.openedUntil) {
			continue
		}
		if key == "" || s.touched.Before(oldest) {
			key, oldest = k, s.touched
		}
	}
	if key == "" {
		return false
	}
	delete(p.entries, key)
	return true
}

// finish releases exactly once. Generations fence late completions: an old
// healthy operation cannot close a newer open circuit or reset its probe.
func (l *protectionLease) finish(outcome protectionOutcome) {
	if l == nil || l.owner == nil {
		return
	}
	l.once.Do(func() {
		p := l.owner
		p.mu.Lock()
		defer p.mu.Unlock()
		s, now := l.state, p.now()
		s.active--
		s.touched = now
		if l.generation != s.generation {
			return
		}
		if l.probe {
			s.probing = false
		}
		switch outcome {
		case protectionSuccess:
			s.failures, s.openedUntil = 0, time.Time{}
			if l.probe {
				s.generation++
			}
		case protectionFailure:
			s.failures++
			if l.probe || s.failures >= CircuitFailureThreshold {
				s.openedUntil = now.Add(CircuitOpenDuration)
				s.generation++
			}
		}
	})
}

// CircuitState returns 0 closed, 1 open or 0.5 half-open for bounded metrics.
// It exposes no active-operation count or caller/credential information.
func (p *Protection) CircuitState(id string) float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.entries[id]
	if s == nil || s.openedUntil.IsZero() {
		return 0
	}
	if s.probing {
		return 0.5
	}
	return 1
}
