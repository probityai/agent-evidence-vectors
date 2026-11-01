"""Client-native MCP allowlists generated from one admit list.

An admit list names the MCP servers an organisation has admitted, each by registry name, version,
content digest, and how it starts: a stdio command with its arguments, or a remote URL. This module
renders that one list into the allowlist each client enforces natively:

* ``claude-code``  the ``allowedMcpServers`` and ``allowManagedMcpServersOnly`` keys of a Claude
                   Code ``managed-settings.json``: one exact ``serverCommand`` per stdio server and
                   one exact ``serverUrl`` per remote server, never a ``serverName`` (a label the
                   user picks, which the Claude Code documentation says is not a security control);
* ``cursor``       the command and URL entries for Cursor's team MCP allowlist;
* ``windsurf``     Server ID and Server Config pairs for the Windsurf team MCP allowlist, every
                   argument a regular expression that matches only its literal value;
* ``registry``     a static MCP registry (the v0.1 API that GitHub Copilot's "registry only"
                   policy and Windsurf's custom registry URLs read), one response body per route.

Every client matches a server by its arguments, its URL or its registry name. None of them hashes
the bytes it is about to run, so the digest an admission bound is carried into the output (the
registry ``_meta`` and the report) but is enforced by no client. The report says, per server and
client, what the client binds. An entry a client cannot express exactly is refused for that client
rather than widened. Standard library only.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

CLIENTS = ("claude-code", "cursor", "windsurf", "registry")
SCHEMA = "https://static.modelcontextprotocol.io/schemas/2025-09-29/server.schema.json"
META_KEY = "io.github.probityai/agent-evidence-admission"

_NAME = re.compile(r"^[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+$")
_KEY = re.compile(r"^[a-zA-Z0-9_-]+$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REGEX_SPECIAL = set("\\^$.|?*+()[]{}")
_REMOTE_TYPES = ("streamable-http", "sse")


@dataclass(frozen=True)
class Server:
    """One admitted server, validated."""

    name: str
    version: str
    description: str
    digest: str
    key: str
    command: tuple[str, ...] = ()
    url: str = ""
    remote_type: str = ""
    package: dict = field(default_factory=dict)

    @property
    def stdio(self) -> bool:
        return bool(self.command)


@dataclass
class Result:
    """What each client got, what each refused, and what each binds."""

    files: dict[str, str] = field(default_factory=dict)
    refused: list[tuple[str, str, str]] = field(default_factory=list)
    binds: list[tuple[str, str, str]] = field(default_factory=list)
    digests: list[tuple[str, str]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.refused

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "files": sorted(self.files),
            "refused": [{"client": c, "server": s, "reason": r} for c, s, r in self.refused],
            "binds": [{"client": c, "server": s, "binds": b} for c, s, b in self.binds],
            "digests_enforced_by_no_client": [{"server": s, "digest": d} for s, d in self.digests],
        }


def _text(entry: dict, name: str, where: str) -> str:
    value = entry.get(name)
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{where}: {name} must be a non-empty string with no outer whitespace")
    return value


def _stdio(entry: dict, where: str) -> tuple[str, ...]:
    stdio = entry["stdio"]
    if not isinstance(stdio, dict):
        raise TypeError(f"{where}.stdio: must be an object")
    command = _text(stdio, "command", f"{where}.stdio")
    args = stdio.get("args", [])
    if not isinstance(args, list) or not all(isinstance(a, str) and a for a in args):
        raise ValueError(f"{where}.stdio: args must be a list of non-empty strings")
    argv = (command, *args)
    if any("${" in part for part in argv):
        raise ValueError(f"{where}.stdio: ${{...}} expands on the user's machine, so the match would not be exact")
    return argv


def _remote(entry: dict, where: str) -> tuple[str, str]:
    remote = entry["remote"]
    if not isinstance(remote, dict):
        raise TypeError(f"{where}.remote: must be an object")
    url = _text(remote, "url", f"{where}.remote")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError(f"{where}.remote: url must be an https URL with a host")
    if "*" in url or "${" in url:
        raise ValueError(f"{where}.remote: url must be exact, with no wildcard and no ${{...}}")
    kind = remote.get("type", "streamable-http")
    if kind not in _REMOTE_TYPES:
        raise ValueError(f"{where}.remote: type must be one of {', '.join(_REMOTE_TYPES)}")
    return url, kind


def _server(entry: object, index: int) -> Server:
    where = f"admitted[{index}]"
    if not isinstance(entry, dict):
        raise TypeError(f"{where}: must be an object")
    name = _text(entry, "name", where)
    if not _NAME.match(name):
        raise ValueError(f"{where}: name must be a registry name such as io.github.owner/server")
    version = _text(entry, "version", where)
    if version == "latest":
        raise ValueError(f"{where}: version must name one release, not latest")
    digest = _text(entry, "digest", where)
    if not _DIGEST.match(digest):
        raise ValueError(f"{where}: digest must be sha256: and 64 lowercase hex digits")
    key = entry.get("key", name.split("/", 1)[1])
    if not isinstance(key, str) or not _KEY.match(key):
        raise ValueError(f"{where}: key must be letters, digits, hyphens and underscores")
    package = entry.get("package", {})
    if not isinstance(package, dict) or not all(isinstance(package.get(k, ""), str) for k in ("registryType", "identifier")):
        raise ValueError(f"{where}: package must be an object with string registryType and identifier")
    if ("stdio" in entry) == ("remote" in entry):
        raise ValueError(f"{where}: give exactly one of stdio and remote")
    description = _text(entry, "description", where)
    if "stdio" in entry:
        return Server(name=name, version=version, description=description, digest=digest, key=key, package=package, command=_stdio(entry, where))
    url, kind = _remote(entry, where)
    return Server(name=name, version=version, description=description, digest=digest, key=key, package=package, url=url, remote_type=kind)


def parse_admit_list(document: object) -> list[Server]:
    """Validate an admit list (``{"admitted": [...]}``) and return its servers in order."""
    if not isinstance(document, dict) or not isinstance(document.get("admitted"), list) or not document["admitted"]:
        raise ValueError("the admit list must be an object with a non-empty admitted array")
    servers = [_server(entry, i) for i, entry in enumerate(document["admitted"])]
    seen: set[tuple[str, str]] = set()
    for server in servers:
        if (server.name, server.version) in seen:
            raise ValueError(f"{server.name} {server.version} is admitted twice")
        seen.add((server.name, server.version))
    keys: dict[str, str] = {}
    for server in servers:
        if keys.setdefault(server.key, server.name) != server.name:
            raise ValueError(f"key {server.key} names both {keys[server.key]} and {server.name}")
    return servers


def _dump(value: object) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def _label(server: Server) -> str:
    return f"{server.name}@{server.version}"


def _claude_code(servers: list[Server], result: Result) -> None:
    allowed: list[dict[str, Any]] = []
    for server in servers:
        if server.stdio:
            allowed.append({"serverCommand": list(server.command)})
            result.binds.append(("claude-code", _label(server), "command and every argument, exactly"))
        else:
            allowed.append({"serverUrl": server.url})
            result.binds.append(("claude-code", _label(server), "the URL, exactly"))
    unique = [e for i, e in enumerate(allowed) if e not in allowed[:i]]
    result.files["claude-code/managed-settings.json"] = _dump({"allowManagedMcpServersOnly": True, "allowedMcpServers": unique})


def _cursor(servers: list[Server], result: Result) -> None:
    entries = []
    for server in servers:
        if not server.stdio:
            entries.append({"server": server.key, "entry": server.url})
            result.binds.append(("cursor", _label(server), "the URL, exactly"))
            continue
        bad = [a for a in server.command if "*" in a or re.search(r"\s", a)]
        if bad:
            result.refused.append(("cursor", _label(server), f"Cursor joins arguments with spaces and reads * as a wildcard, so {bad[0]!r} cannot match exactly"))
            continue
        command, *args = server.command
        absolute = command.startswith("/")
        head = command if absolute else f"*/{command}"
        entries.append({"server": server.key, "entry": " ".join([head, *args])})
        how = "command and every argument, exactly" if absolute else "every argument exactly; the command by name in any directory, because Cursor matches the resolved path"
        result.binds.append(("cursor", _label(server), how))
    result.files["cursor/mcp-allowlist.json"] = _dump({"entries": entries})


def _literal(text: str) -> str:
    return "".join(f"\\{c}" if c in _REGEX_SPECIAL else c for c in text)


def _windsurf(servers: list[Server], result: Result) -> None:
    entries = []
    for server in servers:
        if server.stdio:
            command, *args = server.command
            config = {"command": _literal(command), "args": [_literal(a) for a in args]}
            how = "command and every argument, exactly (anchored literal patterns); env stays free"
        else:
            config = {"serverUrl": _literal(server.url)}
            how = "the server ID and the URL, as an anchored literal pattern"
        entries.append({"serverId": server.key, "serverConfig": config})
        result.binds.append(("windsurf", _label(server), how))
    result.files["windsurf/allowlist.json"] = _dump({"entries": entries})


def _registry_entry(server: Server) -> dict:
    body: dict[str, Any] = {"$schema": SCHEMA, "name": server.name, "description": server.description, "version": server.version}
    if server.stdio:
        package = {"registryType": server.package["registryType"], "identifier": server.package["identifier"], "version": server.version, "transport": {"type": "stdio"}}
        body["packages"] = [package]
    else:
        body["remotes"] = [{"type": server.remote_type, "url": server.url}]
    return {"server": body, "_meta": {META_KEY: {"digest": server.digest}}}


def _registry(servers: list[Server], result: Result) -> None:
    listed: dict[str, dict] = {}
    for server in servers:
        if server.stdio and not (server.package.get("registryType") and server.package.get("identifier")):
            result.refused.append(("registry", _label(server), "a stdio server needs package.registryType and package.identifier to appear in a registry"))
            continue
        entry = _registry_entry(server)
        segment = urllib.parse.quote(server.name, safe="")
        base = f"registry/v0.1/servers/{segment}/versions"
        result.files[f"{base}/{urllib.parse.quote(server.version, safe='')}.json"] = _dump(entry)
        result.files[f"{base}/latest.json"] = _dump(entry)
        listed[server.name] = entry
        result.binds.append(("registry", _label(server), "membership by registry name; the client starts whatever that name resolves to"))
    servers_body = {"servers": list(listed.values()), "metadata": {"count": len(listed)}}
    result.files["registry/v0.1/servers.json"] = _dump(servers_body)


_GENERATORS = {"claude-code": _claude_code, "cursor": _cursor, "windsurf": _windsurf, "registry": _registry}


def generate(servers: list[Server], clients: tuple[str, ...] = CLIENTS) -> Result:
    """Render the admitted servers for each named client. Later versions of a name win ``latest``."""
    result = Result()
    for client in clients:
        _GENERATORS[client](servers, result)
    result.digests = [(_label(s), s.digest) for s in servers]
    return result


def format_report(result: Result) -> str:
    lines = [f"WROTE {path}" for path in sorted(result.files)]
    lines += [f"BINDS {client} {server}: {how}" for client, server, how in result.binds]
    lines += [f"REFUSED {client} {server}: {reason}" for client, server, reason in result.refused]
    lines += [f"UNBOUND {server} {digest}: no client hashes the bytes it starts" for server, digest in result.digests]
    lines.append("PASS every server rendered for every client" if result.ok else f"FAIL {len(result.refused)} refused")
    return "\n".join(lines)
