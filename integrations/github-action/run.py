#!/usr/bin/env python3
"""Narrow, non-logging adapter over the released token-only omp CLI."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
import uuid


class Refused(Exception):
    pass


def require(ok, message):
    if not ok:
        raise Refused(message)


def boolean(name):
    value = os.environ[name]
    require(value in ("true", "false"), "Boolean inputs must be true or false.")
    return value == "true"


def count(value):
    require(type(value) is int and 0 <= value <= 2147483647,
            "Invalid capability count from portal.")
    return value


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "Duplicate JSON configuration key.")
        result[key] = value
    return result


def cli(binary, env, *args):
    # Never echo stdout/stderr, arguments, exceptions or portal-supplied strings.
    result = subprocess.run([binary, *args, "--json"], env=env, capture_output=True,
                            timeout=180, check=False)
    if result.returncode:
        hints = {
            2: "Configuration/policy refused before apply; inspect the omp/v1 declaration in a trusted local job.",
            3: "Check portal TLS URL and the existing publisher token configuration.",
            4: "Token invalid, expired or revoked; ask a team administrator. No authority was recreated.",
            5: "Scope denied: this Action needs team-bound servers:read and servers:write; session-only fields need browser review.",
            7: "Live conflict (409/412/428) or stale review digest: reload and review current state; no automatic retry.",
            8: "Portal rejected configuration (400/422): check origin and auth_value_required. New origins need freshly entered credentials; use the browser for protected credential changes.",
            9: "Portal unavailable, rate limited, or TLS verification failed.",
            11: "Server discovery/test failed; inspect health in the portal. Earlier writes may remain.",
        }
        raise Refused(hints.get(result.returncode, "omp failed; inspect the portal privately. Earlier writes may remain."))
    try:
        return json.loads(result.stdout)
    except (ValueError, UnicodeError):
        raise Refused("Invalid JSON response from omp.") from None


def main():
    team, slug = os.environ["ACTION_TEAM"], os.environ["ACTION_SLUG"]
    for value in (team, slug):
        require(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", value), "Invalid team/server slug.")
    url = os.environ["ACTION_URL"]
    parsed = urlsplit(url)
    require(parsed.scheme == "https" and parsed.hostname and not parsed.username
            and not parsed.password and not parsed.query and not parsed.fragment
            and not any(ord(c) < 33 for c in url), "Portal URL must be HTTPS without credentials/query/fragment.")
    require(re.fullmatch(r"omppub_[A-Za-z0-9_-]{43}", os.environ["ACTION_TOKEN"]),
            "An existing team publisher token is required.")
    refresh = boolean("ACTION_REFRESH")
    fail = boolean("ACTION_FAIL_ON_CHANGES")
    publish = os.environ["ACTION_PUBLISH"]
    require(publish in ("none", "request"), "publish must be none or request.")
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    source = Path(os.environ["ACTION_CONFIG"])
    require(not source.is_absolute() and ".." not in source.parts, "Config path must be relative to workspace.")
    source = workspace / source
    require(not source.is_symlink() and source.resolve().is_relative_to(workspace)
            and source.is_file() and source.stat().st_size <= 1048576, "Unsafe config path or size.")
    # JSON is an unambiguous subset of omp/v1 YAML; no tags, aliases or interpolation.
    doc = json.loads(source.read_text(), object_pairs_hook=pairs)
    require(isinstance(doc, dict) and set(doc) == {"schema", "servers"}
            and doc["schema"] == "omp/v1" and isinstance(doc["servers"], list)
            and len(doc["servers"]) == 1, "Config must be an omp/v1 JSON file containing exactly one server and no platform objects.")
    server = doc["servers"][0]
    require(isinstance(server, dict) and server.get("team") == team and server.get("slug") == slug,
            "Configuration team/slug must match Action inputs.")
    require("publish" not in server, "Set publication only through the publish input.")
    if "authValueEnv" in server:
        require(isinstance(server["authValueEnv"], str)
                and re.fullmatch(r"OMP_SECRET_[A-Z0-9_]+", server["authValueEnv"]),
                "authValueEnv must name an OMP_SECRET_* environment variable, not another credential.")
    output = Path(os.environ["GITHUB_OUTPUT"])
    require(output.is_absolute() and not output.is_symlink()
            and stat.S_ISREG(output.stat().st_mode), "Unsafe GitHub output path.")
    # A minimal child environment: no ambient CLI config, GitHub tokens or auth files.
    env = {k: os.environ[k] for k in ("PATH", "SSL_CERT_FILE", "SSL_CERT_DIR") if k in os.environ}
    env.update({k: v for k, v in os.environ.items() if re.fullmatch(r"OMP_SECRET_[A-Z0-9_]+", k)})
    env.update(OMP_URL=url, OMP_TOKEN=os.environ["ACTION_TOKEN"])
    binary = str(Path(os.environ["ACTION_CLI"]).resolve(strict=True))
    with tempfile.TemporaryDirectory(prefix="omp-action-") as private:
        os.chmod(private, 0o700)
        env.update(HOME=private, XDG_CONFIG_HOME=private, OMP_CONFIG=private + "/absent")
        config = Path(private) / "desired.json"
        config.write_text(json.dumps(doc))
        config.chmod(0o600)
        cli(binary, env, "import", "-f", str(config))
        args = ("--team", team)
        cli(binary, env, "servers", "test", slug, *args)
        changed = 0
        if refresh:
            changed = count(cli(binary, env, "servers", "refresh", slug, *args)["changed"])
        live = cli(binary, env, "servers", "get", slug, *args)
        if publish == "request" and live["publishState"] in ("private", "rejected"):
            digest = live.get("reviewDigest")
            require(isinstance(digest, str) and re.fullmatch(r"[A-Za-z0-9:_-]{1,256}", digest),
                    "Missing/invalid review digest; publication refused.")
            live = cli(binary, env, "servers", "publish", slug, *args, "--expected-digest", digest)
        # 'none' means no publication operation, NOT implicit withdrawal.
        server_id = str(uuid.UUID(live["id"]))
        pending = count(live["pendingChanges"])
        needs = pending > 0 or live["publishState"] == "pending" or changed > 0
        with output.open("a") as stream:
            stream.write(f"server-id={server_id}\nchanged-capabilities={changed}\nneeds-approval={str(needs).lower()}\n")
        if needs:
            # Link only validated origin/path and UUID, never names or portal messages.
            link = url.rstrip("/") + "/teams/" + team + "/servers/" + server_id
            message = "Human review needed; publication request is not approval. Review: " + link
            print(("::error::" if fail else "::warning::") + message)
            return 1 if fail else 0
        print("Server configuration applied and checked; no pending approval observed.")
        return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Refused as exc:
        print("::error::" + str(exc))
        sys.exit(1)
    except Exception:
        print("::error::Action failed safely; inspect configuration and portal privately. Earlier writes may remain.")
        sys.exit(1)
