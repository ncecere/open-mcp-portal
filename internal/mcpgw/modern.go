package mcpgw

import (
	"encoding/json"
	"strconv"

	"github.com/ncecere/open-mcp-portal/internal/buildinfo"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// The modern era's result shape (docs/mcp-protocol.md "Results"):
//
//   - every result carries resultType ("complete", or "input_required" for a
//     multi round-trip request) and our identity in
//     _meta["io.modelcontextprotocol/serverInfo"];
//   - server/discover, the lists and resources/read carry cache hints:
//     ttlMs and cacheScope. The scope is always "private": what a person
//     sees depends on their role and grants, so a shared cache may never
//     serve it to someone else.
//
// Legacy results are left exactly as they were.

const (
	resultComplete      = "complete"
	resultInputRequired = "input_required"

	// listTTLms is how long a client may keep a list or the discovery
	// document: short, because grants and selections can change at any time
	// (the portal sends no list-changed notifications).
	listTTLms = 30_000
	// readTTLms is the freshness of a resource's contents: none. They come
	// live from the server, whose volatility we don't know.
	readTTLms = 0

	cachePrivate = "private"
)

// serverInfo is the gateway's identity as a modern client sees it, the same
// as in the legacy initialize result.
func (rc *request) serverInfo() map[string]any {
	return map[string]any{"name": rc.gateway.Slug, "title": rc.gateway.Name, "version": buildinfo.Version}
}

// cacheable adds the cache hints to a modern result.
func (rc *request) cacheable(result map[string]any, ttlMs int) {
	if rc.modern {
		result["ttlMs"] = ttlMs
		result["cacheScope"] = cachePrivate
	}
}

// shape gives a modern result its resultType and serverInfo (legacy results
// pass untouched). It takes the maps this package builds and the raw JSON of
// a server's relayed result.
func (rc *request) shape(result any) any {
	if !rc.modern || result == nil {
		return result
	}
	switch r := result.(type) {
	case map[string]any:
		if _, ok := r["resultType"]; !ok {
			r["resultType"] = resultComplete
		}
		meta, _ := r["_meta"].(map[string]any)
		if meta == nil {
			meta = map[string]any{}
		}
		meta[metaServerInfo] = rc.serverInfo()
		r["_meta"] = meta
		return r
	case json.RawMessage:
		if out, err := rc.shapeRaw(r); err == nil {
			return json.RawMessage(out)
		}
	}
	return result
}

// shapeRaw is shape for an encoded result object: resultType is "complete"
// (a multi round-trip result from a server is not relayed), and _meta keeps
// whatever else the server put there.
func (rc *request) shapeRaw(encoded []byte) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &obj); err != nil || obj == nil {
		return encoded, err
	}
	obj["resultType"] = json.RawMessage(`"` + resultComplete + `"`)
	if rc.msg.Method == methodRead {
		obj["ttlMs"] = json.RawMessage(strconv.Itoa(readTTLms))
		obj["cacheScope"] = json.RawMessage(`"` + cachePrivate + `"`)
	}
	meta := map[string]json.RawMessage{}
	if raw, ok := obj["_meta"]; ok {
		_ = json.Unmarshal(raw, &meta)
		if meta == nil {
			meta = map[string]json.RawMessage{}
		}
	}
	info, err := json.Marshal(rc.serverInfo())
	if err != nil {
		return nil, err
	}
	meta[metaServerInfo] = info
	m, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	obj["_meta"] = m
	return json.Marshal(obj)
}

// discover answers server/discover (modern requests only): the versions
// served, what this caller's gateway offers, and our identity. The
// capabilities depend on the caller (resources only when the gateway selects
// some they may see), so the result is private like the lists. There are no
// instructions: the legacy initialize result has none.
func (rc *request) discover() {
	caps, err := rc.capabilities()
	if err != nil {
		rc.internal(err)
		return
	}
	if rc.tasksEnabled() {
		// Modern discovery only: the legacy initialize result never lists it.
		caps["extensions"] = map[string]any{upstream.TasksExtension: map[string]any{}}
	}
	result := map[string]any{"supportedVersions": allVersions(), "capabilities": caps}
	rc.cacheable(result, listTTLms)
	rc.reply(result)
}
