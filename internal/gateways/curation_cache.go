package gateways

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"maps"
	"sync"

	"github.com/ncecere/open-mcp-portal/internal/gateways/curation"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// projectionCacheBytes bounds the projected definitions kept. A gateway's
// curated tools are a few kilobytes each; past the bound the cache starts
// again rather than tracking use.
const projectionCacheBytes = 32 << 20

// projection is the result of curation.Project for one definition and policy.
type projection struct {
	definition []byte
	policy     *curation.Policy
	err        error
}

// projections memoises curation.Project. Projecting a curated tool decodes
// its policy, compiles every property schema of the definition (regular
// expressions included) and re-encodes the result; a selection read did that
// for every curated tool on every tools/list and tools/call. The result is a
// pure function of the stored definition and the stored policy, both part of
// the key, so an entry can never be stale: a changed definition or policy is
// a different key. Whether the policy still applies (its base fingerprint,
// the tool's availability) is decided by the caller on every read, as before.
var projections = struct {
	sync.Mutex
	entries map[[sha256.Size]byte]projection
	bytes   int
}{entries: map[[sha256.Size]byte]projection{}}

// projectionKey hashes everything Project reads: the definition and the
// policy columns, each length-prefixed so no two inputs share a key.
func projectionKey(definition []byte, row dbgen.GatewayCapability) [sha256.Size]byte {
	h := sha256.New()
	field := func(b []byte, present bool) {
		var n [9]byte
		if present {
			n[0] = 1
		}
		binary.BigEndian.PutUint64(n[1:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	field(definition, true)
	for _, s := range []*string{row.NameOverride, row.DescriptionOverride} {
		if s == nil {
			field(nil, false)
		} else {
			field([]byte(*s), true)
		}
	}
	field(row.Constraints, true)
	var key [sha256.Size]byte
	h.Sum(key[:0])
	return key
}

// project is curation.Project for a selection row, memoised. Callers get
// their own copies: nothing they do to the result reaches the cache.
func project(definition []byte, row dbgen.GatewayCapability, p *curation.Policy) ([]byte, *curation.Policy, error) {
	key := projectionKey(definition, row)
	projections.Lock()
	hit, ok := projections.entries[key]
	projections.Unlock()
	if !ok {
		hit.definition, hit.policy, hit.err = curation.Project(definition, p)
		projections.Lock()
		if projections.bytes+len(hit.definition) > projectionCacheBytes {
			projections.entries, projections.bytes = map[[sha256.Size]byte]projection{}, 0
		}
		if _, raced := projections.entries[key]; !raced && len(hit.definition) <= projectionCacheBytes {
			projections.entries[key] = hit
			projections.bytes += len(hit.definition)
		}
		projections.Unlock()
	}
	return bytes.Clone(hit.definition), clonePolicy(hit.policy), hit.err
}

func clonePolicy(p *curation.Policy) *curation.Policy {
	if p == nil {
		return nil
	}
	out := &curation.Policy{}
	if p.NameOverride != nil {
		v := *p.NameOverride
		out.NameOverride = &v
	}
	if p.DescriptionOverride != nil {
		v := *p.DescriptionOverride
		out.DescriptionOverride = &v
	}
	if p.Constraints != nil {
		out.Constraints = maps.Clone(p.Constraints)
		for name, c := range out.Constraints {
			c.Fixed = bytes.Clone(c.Fixed)
			if c.Allowed != nil {
				allowed := make([]json.RawMessage, len(c.Allowed))
				for i, v := range c.Allowed {
					allowed[i] = bytes.Clone(v)
				}
				c.Allowed = allowed
			}
			out.Constraints[name] = c
		}
	}
	return out
}
