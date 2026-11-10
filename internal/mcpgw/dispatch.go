package mcpgw

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"go.opentelemetry.io/otel/trace"

	"github.com/ncecere/open-mcp-portal/internal/buildinfo"
	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/toolscope"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

func (rc *request) dispatch() {
	switch rc.msg.Method {
	case methodInitialize:
		rc.initialize()
	case methodDiscover:
		if rc.modern {
			rc.discover()
		} else {
			rc.methodNotFound()
		}
	case methodPing:
		if rc.modern {
			// Removed in 2026-07-28.
			rc.methodNotFound()
			return
		}
		rc.reply(struct{}{})
	case methodToolsList:
		rc.list(upstream.KindTool, "tools")
	case methodPromptsList:
		rc.list(upstream.KindPrompt, "prompts")
	case methodToolsCall:
		rc.call(upstream.KindTool)
	case methodTasksGet, methodTasksUpdate, methodTasksCancel:
		if !rc.modern || !rc.tasksEnabled() {
			// Legacy clients never see tasks, and a portal without the task
			// store does not know the methods at all.
			rc.methodNotFound()
			return
		}
		rc.task()
	case methodPromptsGet:
		rc.call(upstream.KindPrompt)
	case methodResources, methodTemplates, methodRead:
		has, err := rc.hasResources()
		switch {
		case err != nil:
			rc.internal(err)
		case !has:
			rc.methodNotFound()
		case rc.msg.Method == methodResources:
			rc.list(upstream.KindResource, "resources")
		case rc.msg.Method == methodTemplates:
			rc.list(upstream.KindResourceTemplate, "resourceTemplates")
		default:
			rc.read()
		}
	default:
		rc.methodNotFound()
	}
}

// methodNotFound answers an unknown method: 200 as always, and 404 in the
// modern era (streamable-http, "Protocol Version Header").
func (rc *request) methodNotFound() {
	status := http.StatusOK
	if rc.modern {
		status = http.StatusNotFound
	}
	writeRPC(rc.w, status, rc.msg.ID, nil, &rpcError{Code: codeMethodNotFound, Message: "Method not found: " + clip(rc.msg.Method, 100)})
}

// hasResources reports whether the gateway selects any resource or
// resource template (whether or not served now): only then does it
// advertise and serve the resources methods.
func (rc *request) hasResources() (bool, error) {
	all, err := rc.h.Gateways.Offers(rc.r.Context(), rc.gateway, rc.caller)
	if err != nil {
		return false, err
	}
	for _, o := range all {
		if gateways.IsResourceKind(o.Capability.Kind) {
			return true, nil
		}
	}
	return false, nil
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// initialize negotiates the protocol version (the client's when supported,
// else the newest) and advertises tools and prompts, and resources when the
// gateway selects any (no subscriptions).
func (rc *request) initialize() {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if len(rc.msg.Params) > 0 && json.Unmarshal(rc.msg.Params, &p) != nil {
		rc.fail(codeInvalidParams, "Invalid initialize parameters")
		return
	}
	version := protocolVersions[0]
	if slices.Contains(protocolVersions, p.ProtocolVersion) {
		version = p.ProtocolVersion
	}
	caps, err := rc.capabilities()
	if err != nil {
		rc.internal(err)
		return
	}
	rc.reply(map[string]any{
		"protocolVersion": version,
		"capabilities":    caps,
		"serverInfo":      map[string]any{"name": rc.gateway.Slug, "title": rc.gateway.Name, "version": buildinfo.Version},
	})
}

// capabilities are what the gateway advertises to this caller: tools and
// prompts, and resources when the gateway selects any (no subscriptions, no
// list change notifications).
func (rc *request) capabilities() (map[string]any, error) {
	caps := map[string]any{
		"tools":   map[string]any{"listChanged": false},
		"prompts": map[string]any{"listChanged": false},
	}
	has, err := rc.hasResources()
	if err != nil {
		return nil, err
	}
	if has {
		caps["resources"] = map[string]any{"listChanged": false, "subscribe": false}
	}
	return caps, nil
}

// offers reads what the caller may use of kind now, by exposed name.
func (rc *request) offers(kind string) ([]gateways.Offer, error) {
	sp := rc.span("mcp.authorize", trace.SpanKindInternal)
	all, err := rc.h.Gateways.Offers(rc.r.Context(), rc.gateway, rc.caller)
	sp.End()
	if err != nil {
		return nil, err
	}
	out := make([]gateways.Offer, 0, len(all))
	for _, o := range all {
		if o.Capability.Kind == kind {
			if o.Allowed && kind == upstream.KindTool && !rc.principal.toolPolicy.Allows(toolscope.Class(o.Capability.ToolClass), o.ExposedName) {
				o.Allowed = false
				o.Denied = gateways.DeniedToolScope
			}
			out = append(out, o)
		}
	}
	slices.SortFunc(out, func(a, b gateways.Offer) int { return strings.Compare(a.ExposedName, b.ExposedName) })
	return out, nil
}

// listed is a stored definition with the exposed name (tools, prompts) or
// URI (resources: uri, templates: uriTemplate); a resource's own name,
// title, description and mimeType stay as approved.
func listed(o gateways.Offer) (json.RawMessage, error) { return listedFor(o, false) }

// listedFor is listed for an era: the modern era allows any JSON Schema as
// outputSchema, so it is passed through; legacy clients get only object
// schemas.
func listedFor(o gateways.Offer, modern bool) (json.RawMessage, error) {
	def := map[string]json.RawMessage{}
	raw := o.EffectiveDefinition
	if len(raw) == 0 {
		raw = o.Capability.Definition
	} // callers constructing an uncurated offer
	if err := json.Unmarshal(raw, &def); err != nil {
		return nil, err
	}
	exposed, _ := json.Marshal(o.ExposedName)
	switch o.Capability.Kind {
	case upstream.KindResource:
		def["uri"] = exposed
	case upstream.KindResourceTemplate:
		def["uriTemplate"] = exposed
	default:
		def["name"] = exposed
	}
	if o.Capability.Kind == upstream.KindTool && o.Capability.ToolClass != nil {
		annotations := map[string]json.RawMessage{}
		if err := json.Unmarshal(def["annotations"], &annotations); err != nil || annotations == nil {
			annotations = map[string]json.RawMessage{}
		}
		readOnly, _ := json.Marshal(*o.Capability.ToolClass == registry.ClassRead)
		destructive, _ := json.Marshal(*o.Capability.ToolClass == registry.ClassDestructive)
		annotations["readOnlyHint"], annotations["destructiveHint"] = readOnly, destructive
		def["annotations"], _ = json.Marshal(annotations)
	}
	delete(def, "_meta")
	if raw, ok := def["outputSchema"]; ok && !modern && !objectSchema(raw) {
		// The MCP schema requires an outputSchema of type "object"; strict
		// clients reject the whole list when one isn't (GitHub's server
		// lists ["null","array"] and oneOf schemas). Without it, results
		// still carry structuredContent, just unvalidated by the client.
		delete(def, "outputSchema")
	}
	return json.Marshal(def)
}

// objectSchema reports whether a tool's outputSchema has "type": "object",
// as the MCP schema requires.
func objectSchema(raw json.RawMessage) bool {
	var s struct {
		Type json.RawMessage `json:"type"`
	}
	if json.Unmarshal(raw, &s) != nil {
		return false
	}
	var t string
	return json.Unmarshal(s.Type, &t) == nil && t == "object"
}

// list serves tools/list, prompts/list, resources/list or
// resources/templates/list from the approved definitions, paged by size;
// the cursor is the last exposed name (or URI) of the page.
func (rc *request) list(kind, key string) {
	var p struct {
		Cursor string `json:"cursor"`
	}
	if len(rc.msg.Params) > 0 && json.Unmarshal(rc.msg.Params, &p) != nil {
		n := rc.fail(codeInvalidParams, "Invalid list parameters")
		rc.record(calls.Call{Outcome: calls.OutcomeBadRequest, ErrorClass: "invalid_params"}, n)
		return
	}
	after := ""
	if p.Cursor != "" {
		b, err := base64.RawURLEncoding.DecodeString(p.Cursor)
		if err != nil || len(b) == 0 {
			n := rc.fail(codeInvalidParams, "Invalid cursor")
			rc.record(calls.Call{Outcome: calls.OutcomeBadRequest, ErrorClass: "invalid_cursor"}, n)
			return
		}
		after = string(b)
	}
	offers, err := rc.offers(kind)
	if err != nil {
		rc.internal(err)
		return
	}
	items := []json.RawMessage{}
	size, last, next := 0, "", ""
	for _, o := range offers {
		if !o.Allowed || (after != "" && o.ExposedName <= after) {
			continue
		}
		def, err := listedFor(o, rc.modern)
		if err != nil {
			rc.internal(err)
			return
		}
		if size+len(def) > listPageBytes && len(items) > 0 {
			next = base64.RawURLEncoding.EncodeToString([]byte(last))
			break
		}
		size, last = size+len(def), o.ExposedName
		items = append(items, def)
	}
	result := map[string]any{key: items}
	if next != "" {
		result["nextCursor"] = next
	}
	rc.cacheable(result, listTTLms)
	n := rc.reply(result)
	rc.record(calls.Call{Outcome: calls.OutcomeOK}, n)
}
