package upstream

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Discovery is what a server listed.
type Discovery struct {
	ServerName, ServerVersion, ProtocolVersion string
	// Protocol is the era and version negotiated.
	Protocol     Protocol
	Capabilities []Capability
	Latency      time.Duration
	// SupportsTasks: a MODERN server's discovery advertised the Tasks
	// extension. A legacy server, or the extension's absence, is false. This is
	// metadata for the gateway's negotiation decision, never an authorization.
	SupportsTasks bool
}

// Discover connects to a server and reads its tools, resources, resource
// templates and prompts (every page, at most MaxPerKind of each). Kinds the
// server doesn't advertise are not read. It never calls a tool. Failures
// are *Error.
func (c *Client) Discover(ctx context.Context, t Target) (Discovery, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	sess, proto, err := c.open(ctx, t)
	if err != nil {
		return Discovery{Latency: time.Since(start)}, err
	}
	defer sess.close()
	d := Discovery{Protocol: proto}
	var caps *mcp.ServerCapabilities
	if res := sess.cs.InitializeResult(); res != nil {
		caps = res.Capabilities
		d.SupportsTasks = proto.Era == EraModern && caps != nil && hasTasksExtension(caps.Extensions)
		d.ProtocolVersion = clip(res.ProtocolVersion, 100)
		if res.ServerInfo != nil {
			d.ServerName, d.ServerVersion = clip(res.ServerInfo.Name, 200), clip(res.ServerInfo.Version, 100)
		}
	}
	steps := []struct {
		advertised bool
		list       func() ([]Capability, error)
	}{
		{caps == nil || caps.Tools != nil, func() ([]Capability, error) { return c.listTools(ctx, t, sess) }},
		{caps == nil || caps.Resources != nil, func() ([]Capability, error) { return c.listResources(ctx, t, sess) }},
		{caps == nil || caps.Resources != nil, func() ([]Capability, error) { return c.listResourceTemplates(ctx, t, sess) }},
		{caps == nil || caps.Prompts != nil, func() ([]Capability, error) { return c.listPrompts(ctx, t, sess) }},
	}
	for _, s := range steps {
		if !s.advertised {
			continue
		}
		listed, err := s.list()
		if err != nil {
			d.Latency = time.Since(start)
			return d, err
		}
		d.Capabilities = append(d.Capabilities, listed...)
	}
	d.Latency = time.Since(start)
	return d, nil
}

// pager reads every page of one kind's list. page returns a page's
// capabilities (already converted) and the next cursor.
func (c *Client) pager(ctx context.Context, t Target, sess *session, kind string, page func(cursor string) ([]Capability, string, error)) ([]Capability, error) {
	var out []Capability
	seen := map[string]bool{}
	cursors := map[string]bool{}
	cursor := ""
	for pages := 0; ; pages++ {
		if pages >= maxPages {
			return nil, &Error{Class: ClassBadResponse, Message: fmt.Sprintf("The server's %s list has more than %d pages.", kindLabel(kind), maxPages)}
		}
		items, next, err := page(cursor)
		if err != nil {
			var e *Error
			if errors.As(err, &e) {
				return nil, e
			}
			if pages == 0 && methodNotFound(err) {
				return nil, nil // advertised, but not served: nothing of this kind
			}
			return nil, c.classify(ctx, t, sess.ex, err)
		}
		for _, cp := range items {
			if !validName(cp.Name) || seen[cp.Name] {
				continue
			}
			if len(out) >= MaxPerKind {
				return nil, &Error{Class: ClassTooLarge, Message: fmt.Sprintf("The server lists more than %d %ss.", MaxPerKind, kindLabel(kind))}
			}
			seen[cp.Name] = true
			out = append(out, cp)
		}
		if next == "" {
			return out, nil
		}
		if cursors[next] || len(next) > 4096 {
			return nil, &Error{Class: ClassBadResponse, Message: fmt.Sprintf("The server's %s list repeats a page.", kindLabel(kind))}
		}
		cursors[next] = true
		cursor = next
	}
}

func methodNotFound(err error) bool {
	var rpc *jsonrpc.Error
	return errors.As(err, &rpc) && rpc.Code == jsonrpc.CodeMethodNotFound
}

func (c *Client) listTools(ctx context.Context, t Target, sess *session) ([]Capability, error) {
	return c.pager(ctx, t, sess, KindTool, func(cursor string) ([]Capability, string, error) {
		res, err := sess.cs.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return nil, "", err
		}
		out := make([]Capability, 0, len(res.Tools))
		for _, tool := range res.Tools {
			if tool == nil {
				continue
			}
			v := *tool
			v.Title, v.Description = clip(v.Title, MaxTitle), clip(v.Description, MaxDescription)
			title := v.Title
			if title == "" && v.Annotations != nil {
				title = clip(v.Annotations.Title, MaxTitle)
			}
			cp, err := newCapability(KindTool, v.Name, title, v.Description, &v)
			if err != nil {
				return nil, "", err
			}
			out = append(out, cp)
		}
		return out, res.NextCursor, nil
	})
}

func (c *Client) listResources(ctx context.Context, t Target, sess *session) ([]Capability, error) {
	return c.pager(ctx, t, sess, KindResource, func(cursor string) ([]Capability, string, error) {
		res, err := sess.cs.ListResources(ctx, &mcp.ListResourcesParams{Cursor: cursor})
		if err != nil {
			return nil, "", err
		}
		out := make([]Capability, 0, len(res.Resources))
		for _, r := range res.Resources {
			if r == nil {
				continue
			}
			v := *r
			v.Title, v.Description = clip(v.Title, MaxTitle), clip(v.Description, MaxDescription)
			title := v.Title
			if title == "" {
				title = clip(v.Name, MaxTitle)
			}
			cp, err := newCapability(KindResource, v.URI, title, v.Description, &v)
			if err != nil {
				return nil, "", err
			}
			out = append(out, cp)
		}
		return out, res.NextCursor, nil
	})
}

func (c *Client) listResourceTemplates(ctx context.Context, t Target, sess *session) ([]Capability, error) {
	return c.pager(ctx, t, sess, KindResourceTemplate, func(cursor string) ([]Capability, string, error) {
		res, err := sess.cs.ListResourceTemplates(ctx, &mcp.ListResourceTemplatesParams{Cursor: cursor})
		if err != nil {
			return nil, "", err
		}
		out := make([]Capability, 0, len(res.ResourceTemplates))
		for _, r := range res.ResourceTemplates {
			if r == nil {
				continue
			}
			v := *r
			v.Title, v.Description = clip(v.Title, MaxTitle), clip(v.Description, MaxDescription)
			title := v.Title
			if title == "" {
				title = clip(v.Name, MaxTitle)
			}
			cp, err := newCapability(KindResourceTemplate, v.URITemplate, title, v.Description, &v)
			if err != nil {
				return nil, "", err
			}
			out = append(out, cp)
		}
		return out, res.NextCursor, nil
	})
}

func (c *Client) listPrompts(ctx context.Context, t Target, sess *session) ([]Capability, error) {
	return c.pager(ctx, t, sess, KindPrompt, func(cursor string) ([]Capability, string, error) {
		res, err := sess.cs.ListPrompts(ctx, &mcp.ListPromptsParams{Cursor: cursor})
		if err != nil {
			return nil, "", err
		}
		out := make([]Capability, 0, len(res.Prompts))
		for _, p := range res.Prompts {
			if p == nil {
				continue
			}
			v := *p
			v.Title, v.Description = clip(v.Title, MaxTitle), clip(v.Description, MaxDescription)
			cp, err := newCapability(KindPrompt, v.Name, v.Title, v.Description, &v)
			if err != nil {
				return nil, "", err
			}
			out = append(out, cp)
		}
		return out, res.NextCursor, nil
	})
}
