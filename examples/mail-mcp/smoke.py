#!/usr/bin/env python3
"""Smoke test of the mail MCP example against a local development portal (Open MCP Portal).

Sets up (idempotently) and leaves in place, so you can try it:
  - auth provider "google-dev" pointing at the fake OAuth provider (make fake-oauth)
  - server "mail" in team "demo" (this example, -fake-gmail) requiring google-dev with gmail.readonly,
    with create_draft overridden to gmail.compose
  - team gateway "mail" in team demo with the server's three tools

Then, as admin@localhost (dev sign-in), with a temporary API key "qa-mail-key":
  1. a call without consent answers -32042 with a consent link; the script consents like a browser would
  2. search_messages and read_message return the fake mailbox; create_draft asks again (gmail.compose) and works
  3. a server registered without a requirement ("qa-mail-noreq") gets the clear tool error
  4. calling the example directly without (or with a forged) identity token gets 401
and removes every qa-mail-* object and the admin's google-dev connection afterwards (so you see the consent
flow yourself).

Needs: make run (DEV_AUTH=true, APP_URL=http://localhost:8088), make dev-seed, make fake-oauth, and
make example-mail-fake (the example on http://127.0.0.1:8093/mcp with -provider google-dev).
Usage: python3 examples/mail-mcp/smoke.py [--app URL] [--mcp URL] [--oauth URL]
"""
import argparse
import base64
import http.cookiejar
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

READONLY = "https://www.googleapis.com/auth/gmail.readonly"
COMPOSE = "https://www.googleapis.com/auth/gmail.compose"
PROVIDER, SERVER, GATEWAY, TEAM = "google-dev", "mail", "mail", "demo"
QA = "qa-mail-"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Session:
    def __init__(self, base, account):
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect)
        self.csrf = None
        status, _, _ = self.call("POST", "/auth/dev", {"account": account})
        if status != 200:
            sys.exit(f"dev sign-in as {account} failed ({status}); is DEV_AUTH on and APP_URL {self.base}?")
        self.csrf = self.must("GET", "/v1/me")["csrfToken"]

    def call(self, method, url, body=None, headers=None):
        if url.startswith("/"):
            url = self.base + url
        h = {"Origin": self.base, "Content-Type": "application/json"}
        if self.csrf:
            h["X-CSRF-Token"] = self.csrf
        h.update(headers or {})
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        try:
            with self.opener.open(req) as r:
                return r.status, r.headers, decode(r.read())
        except urllib.error.HTTPError as e:
            return e.code, e.headers, decode(e.read())

    def must(self, method, path, body=None, headers=None, ok=(200, 201)):
        status, _, out = self.call(method, path, body, headers)
        if status not in ok:
            sys.exit(f"FAIL {method} {path} -> {status}: {out}")
        return out["data"] if isinstance(out, dict) and "data" in out else out


def decode(raw):
    text = raw.decode(errors="replace")
    try:
        return json.loads(text) if text else None
    except ValueError:
        return text


def mcp(app, gateway, key, method, params=None):
    body = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    req = urllib.request.Request(f"{app}/mcp/{gateway}", data=json.dumps(body).encode(), method="POST", headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        sys.exit(f"FAIL {method} on gateway {gateway}: HTTP {e.code} {e.read()[:300]!r}")


def call_tool(app, gateway, key, name, args):
    return mcp(app, gateway, key, "tools/call", {"name": name, "arguments": args})


def ok(msg):
    print(f"  ok  {msg}")


def check(cond, msg, detail=None):
    if not cond:
        sys.exit(f"FAIL {msg}" + (f": {detail}" if detail is not None else ""))
    ok(msg)


def consent(s, out, provider_id, oauth):
    """Answer a -32042 like the person would: open the link, Continue, approve at the provider."""
    err = out.get("error") or {}
    check(err.get("code") == -32042, "call without consent answers -32042", out)
    el = err["data"]["elicitations"][0]
    link = el["url"]
    check(f"/connect/{PROVIDER}?request=" in link and link in err["message"], f"consent link {link.split('?')[0]}?request=…")
    rid = link.split("?request=")[1]
    req = s.must("GET", f"/v1/connect/requests/{rid}")
    print(f"      consent page: {req['capability']['exposedName']} in gateway {req['gateway']['slug']}, scopes {req['requestScopes']}")
    started = s.must("POST", "/v1/me/connections/start", {"providerId": provider_id, "requestId": rid})
    # The fake provider shows Approve/Deny unless started with -auto; Approve adds decision=approve.
    authorize = started["authorizeUrl"] + "&decision=approve"
    check(authorize.startswith(oauth), "authorization URL goes to the fake provider")
    status, headers, _ = s.call("GET", authorize)
    check(status == 302, "fake provider approves and redirects to /connect/callback", status)
    status, headers, _ = s.call("GET", headers["Location"])
    check(status == 303 and "result=connected" in headers.get("Location", ""), "callback stores the connection",
          (status, headers.get("Location")))


def structured(out, msg):
    res = out.get("result")
    if not res or res.get("isError"):
        sys.exit(f"FAIL {msg}: {out}")
    return res.get("structuredContent") or {}


def find(items, key, value):
    return next((i for i in items if i.get(key) == value), None)


def caps_of(s, server_id):
    return s.must("GET", f"/v1/teams/{TEAM}/mcp-servers/{server_id}/capabilities")


def direct(mcp_url, headers):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "search_messages", "arguments": {"query": ""}}}).encode()
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    h.update(headers)
    try:
        with urllib.request.urlopen(urllib.request.Request(mcp_url, data=body, method="POST", headers=h)) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def cleanup(s, app):
    """Delete qa-mail-* objects (also from an earlier, failed run) and the admin's google-dev connection."""
    for g in s.must("GET", f"/v1/teams/{TEAM}/gateways?q={QA}")["items"]:
        if g["slug"].startswith(QA):
            s.must("DELETE", f"/v1/teams/{TEAM}/gateways/{g['id']}")
            print(f"  cleanup: deleted gateway {g['slug']}")
    for sv in s.must("GET", f"/v1/teams/{TEAM}/mcp-servers?q={QA}")["items"]:
        if sv["slug"].startswith(QA):
            s.must("DELETE", f"/v1/teams/{TEAM}/mcp-servers/{sv['id']}")
            print(f"  cleanup: deleted server {sv['slug']}")
    for k in s.must("GET", "/v1/me/api-keys"):
        if k["name"].startswith(QA) and not k.get("revokedAt"):
            s.must("DELETE", f"/v1/me/api-keys/{k['id']}")
            print(f"  cleanup: revoked API key {k['name']}")
    for c in s.must("GET", "/v1/me/connections"):
        if c["provider"]["slug"] == PROVIDER:
            s.must("DELETE", f"/v1/me/connections/{c['id']}")
            print(f"  cleanup: disconnected admin@localhost from {PROVIDER}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", default="http://localhost:8088")
    ap.add_argument("--mcp", default="http://127.0.0.1:8093/mcp", help="the example's URL (its -audience)")
    ap.add_argument("--oauth", default="http://127.0.0.1:8092", help="the fake OAuth provider")
    args = ap.parse_args()
    app = args.app.rstrip("/")
    s = Session(app, "admin")

    print("setup (kept)")
    cleanup(s, app)
    providers = s.must("GET", "/v1/admin/auth-providers")
    provider = find(providers, "slug", PROVIDER)
    if provider is None:
        provider = s.must("POST", "/v1/admin/auth-providers", {
            "slug": PROVIDER, "name": "Google (dev, fake)", "preset": "google", "clientId": "fake-client",
            "clientSecret": "fake-secret-0123456789", "authorizationUrl": f"{args.oauth}/authorize",
            "tokenUrl": f"{args.oauth}/token", "revocationUrl": f"{args.oauth}/revoke", "userinfoUrl": f"{args.oauth}/userinfo",
            "defaultScopes": ["openid", "https://www.googleapis.com/auth/userinfo.email"]})
        ok(f"created auth provider {PROVIDER} -> {args.oauth}")
    else:
        ok(f"auth provider {PROVIDER} exists")
    if provider.get("accessMode") != "open":
        # A provider made through the API starts restricted with nobody listed (decision 69); this dev one is open to every team.
        s.must("PUT", f"/v1/admin/auth-providers/{provider['id']}/access", {"accessMode": "open", "teamIds": [], "serverIds": []},
               {"If-Match": f'"{provider["revision"]}"'})
        provider = s.must("GET", f"/v1/admin/auth-providers/{provider['id']}")
        ok(f"opened auth provider {PROVIDER} to every team")

    requirement = {"providerId": provider["id"], "scopes": [READONLY]}
    server = find(s.must("GET", f"/v1/teams/{TEAM}/mcp-servers?q={SERVER}")["items"], "slug", SERVER)
    if server is None:
        created = s.must("POST", f"/v1/teams/{TEAM}/mcp-servers", {
            "slug": SERVER, "name": "Mail (Gmail)", "url": args.mcp, "requirement": requirement,
            "description": "Gmail through the portal's delegated Google token (examples/mail-mcp)"})
        server = created["server"]
        if created.get("refreshError"):
            sys.exit(f"FAIL discovery: {created['refreshError']}; is make example-mail-fake running?")
        ok(f"registered server {SERVER} ({args.mcp}) requiring {PROVIDER} {READONLY.rsplit('/', 1)[1]}")
    else:
        req = server.get("requirement") or {}
        if (req.get("provider") or {}).get("slug") != PROVIDER or READONLY not in (req.get("scopes") or []):
            server = s.must("PATCH", f"/v1/teams/{TEAM}/mcp-servers/{server['id']}", {"requirement": requirement},
                            {"If-Match": f'"{server["revision"]}"'})
            ok(f"set server {SERVER}'s requirement")
        s.must("POST", f"/v1/teams/{TEAM}/mcp-servers/{server['id']}/refresh")
        ok(f"server {SERVER} exists (refreshed)")
    caps = {c["name"]: c for c in caps_of(s, server["id"]) if c["kind"] == "tool" and not c.get("gone")}
    check(set(caps) >= {"search_messages", "read_message", "create_draft"}, "server lists the three tools", sorted(caps))
    draft = caps["create_draft"]
    if (draft.get("requirementOverride") or {}).get("mode") != "scopes":
        cur = s.must("GET", f"/v1/teams/{TEAM}/mcp-servers/{server['id']}")
        s.must("PUT", f"/v1/teams/{TEAM}/mcp-servers/{server['id']}/capabilities/{draft['id']}/requirement",
               {"mode": "scopes", "scopes": [COMPOSE]}, {"If-Match": f'"{cur["revision"]}"'})
    ok("create_draft overridden to gmail.compose")

    gw = find(s.must("GET", f"/v1/teams/{TEAM}/gateways?q={GATEWAY}")["items"], "slug", GATEWAY)
    if gw is None:
        gw = s.must("POST", f"/v1/teams/{TEAM}/gateways", {"slug": GATEWAY, "name": "Mail",
                                                         "description": "Gmail tools (examples/mail-mcp)"})
        ok(f"created team gateway {GATEWAY}")
    sel = s.must("GET", f"/v1/teams/{TEAM}/gateways/{gw['id']}/capabilities")
    items = [{k: v for k, v in i.items() if k in ("capabilityId", "minTeamRole") and v is not None} for i in sel["items"]]
    have = {i["capabilityId"] for i in items}
    missing = [c["id"] for c in caps.values() if c["id"] not in have]
    if missing:
        s.must("PUT", f"/v1/teams/{TEAM}/gateways/{gw['id']}/capabilities",
               {"items": items + [{"capabilityId": m} for m in missing]}, {"If-Match": f'"{sel["revision"]}"'})
    ok(f"gateway {GATEWAY} selects the mail tools ({gw['url']})")

    print("smoke (as admin@localhost)")
    key = s.must("POST", "/v1/me/api-keys", {"name": f"{QA}key", "expiresInDays": 1})["secret"]
    try:
        names = [t["name"] for t in mcp(app, GATEWAY, key, "tools/list")["result"]["tools"]]
        check({"mail__search_messages", "mail__read_message", "mail__create_draft"} <= set(names), "tools/list through the gateway",
              names)

        consent(s, call_tool(app, GATEWAY, key, "mail__search_messages", {"query": "from:alice"}), provider["id"], args.oauth)
        found = structured(call_tool(app, GATEWAY, key, "mail__search_messages", {"query": "from:alice"}), "search after consent")
        msgs = found.get("messages", [])
        check(len(msgs) == 2, f"search_messages from:alice -> {len(msgs)} messages")
        for m in msgs:
            print(f"      {m['id']}  {m['date'][:16]}  {m['from']}  | {m['subject']}")
        msg = structured(call_tool(app, GATEWAY, key, "mail__read_message", {"id": msgs[0]["id"]}), "read_message")
        check(msg.get("truncated") is True and len(msg["body"]) == 20000, "read_message returns headers and a truncated body",
              (msg.get("truncated"), len(msg.get("body", ""))))
        print(f"      Subject: {msg['headers']['Subject']}  body: {msg['body'][:60]!r}…")

        draft_args = {"to": "bob@example.com", "subject": "Re: Lunch on Friday?", "body": "Friday at noon works."}
        consent(s, call_tool(app, GATEWAY, key, "mail__create_draft", draft_args), provider["id"], args.oauth)
        d = structured(call_tool(app, GATEWAY, key, "mail__create_draft", draft_args), "create_draft after consent")
        check(bool(d.get("draftId")), f"create_draft (gmail.compose) -> draft {d.get('draftId')}")
        conn = find(s.must("GET", "/v1/me/connections"), "status", "active")
        check(conn and {READONLY, COMPOSE} <= set(conn["scopes"]), "the connection holds both scopes (union)", conn and conn["scopes"])

        # A server registered without a requirement: no token, a clear tool error.
        created = s.must("POST", f"/v1/teams/{TEAM}/mcp-servers", {"slug": f"{QA}noreq", "name": "QA mail without requirement",
                                                                  "url": args.mcp})
        noreq = created["server"]
        qgw = s.must("POST", f"/v1/teams/{TEAM}/gateways", {"slug": f"{QA}noreq", "name": "QA mail no requirement"})
        cid = find([c for c in caps_of(s, noreq["id"]) if c["kind"] == "tool"], "name", "search_messages")["id"]
        s.must("PUT", f"/v1/teams/{TEAM}/gateways/{qgw['id']}/capabilities", {"items": [{"capabilityId": cid}]},
               {"If-Match": f'"{qgw["revision"]}"'})
        out = call_tool(app, f"{QA}noreq", key, f"{QA}noreq__search_messages", {"query": ""})
        res = out.get("result") or {}
        text = "".join(c.get("text", "") for c in res.get("content", []))
        check(res.get("isError") and "user authorization requirement" in text, "no requirement -> tool error explaining it", out)
        print(f"      {text[:110]}…")

        # Straight to the example, bypassing the portal.
        check(direct(args.mcp, {}) == 401, "direct tools/call without identity token -> 401")
        check(direct(args.mcp, {"MCP-Gateway-Provider": PROVIDER, "MCP-Gateway-Provider-Token": "stolen"}) == 401,
              "direct tools/call with only provider headers -> 401")
        forged = ".".join(base64.urlsafe_b64encode(json.dumps(p).encode()).rstrip(b"=").decode() for p in (
            {"alg": "ES256", "kid": "forged"}, {"iss": app, "aud": args.mcp, "sub": "x", "provider": PROVIDER})) + ".c2ln"
        check(direct(args.mcp, {"Authorization": f"Bearer {forged}", "MCP-Gateway-Provider": PROVIDER,
                                "MCP-Gateway-Provider-Token": "stolen"}) == 401, "direct tools/call with a forged JWT -> 401")
    finally:
        print("cleanup")
        cleanup(s, app)

    print(f"\nPASS. Try it: gateway {gw['url']} (server {SERVER}, provider {PROVIDER}); sign in at {app} as admin@localhost.")
    print(f"  claude mcp add --transport http mail {gw['url']}")


if __name__ == "__main__":
    main()
