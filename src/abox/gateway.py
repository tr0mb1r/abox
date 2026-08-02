"""Docker MCP Gateway lifecycle — one container per profile on ``abox-net``.

Facts this module is built on, each verified against ``docker/mcp-gateway:v2``
and ``docker mcp`` CLI v0.43.1 rather than assumed:

* The image entrypoint is ``/docker-mcp gateway run``; arguments append to it.
* TCP transports are **authenticated**: without a bearer token the gateway
  answers ``401``. ``MCP_GATEWAY_AUTH_TOKEN`` pins a token abox knows, so the
  agent can be handed exactly one credential — the right to talk to its own
  gateway — instead of the endpoint being open to everything on the bridge.
* ``--host=0.0.0.0`` is required; the default binds loopback inside the
  container and is unreachable from a sibling container.
* The gateway spawns MCP server containers with ``--pull never``, so their
  images must already be on the daemon.
* Secrets never pass through the gateway process: it emits ``-e VAR`` with no
  value and the daemon resolves ``se://docker/mcp/<name>`` from the OS keychain.
* The image ships busybox, so health probes reuse the gateway image itself and
  need no extra pull.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets as pysecrets
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from . import dockerx, paths
from .catalog import Catalog
from .errors import GatewayError
from .manifest import GlobalConfig

MCP_PROTOCOL_VERSION = "2025-06-18"
TOKEN_BYTES = 32


def gateways_dir() -> Path:
    d = paths.state_home() / "gateways"
    d.mkdir(parents=True, exist_ok=True)
    d.chmod(0o700)
    return d


def token_path(profile: str) -> Path:
    return gateways_dir() / f"{profile}.token"


def registry_path(profile: str) -> Path:
    """Which projects use this profile, and what they each need."""
    return gateways_dir() / f"{profile}.json"


def ensure_token(profile: str) -> str:
    """Read (or mint) the profile's gateway bearer token."""
    path = token_path(profile)
    if path.is_file():
        token = path.read_text(encoding="utf-8").strip()
        if token:
            return token
    token = pysecrets.token_urlsafe(TOKEN_BYTES)
    path.write_text(token + "\n", encoding="utf-8")
    path.chmod(0o600)
    return token


def read_token(profile: str) -> str | None:
    path = token_path(profile)
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8").strip() or None


# -- profile registry -----------------------------------------------------


@dataclass
class ProfileRegistry:
    """Union of what every project bound to this profile asks the gateway for."""

    profile: str
    projects: dict[str, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def load(cls, profile: str) -> ProfileRegistry:
        path = registry_path(profile)
        if not path.is_file():
            return cls(profile=profile)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return cls(profile=profile)
        return cls(profile=profile, projects=dict(data.get("projects") or {}))

    def save(self) -> None:
        path = registry_path(self.profile)
        path.write_text(
            json.dumps({"profile": self.profile, "projects": self.projects}, indent=2) + "\n",
            encoding="utf-8",
        )
        path.chmod(0o600)

    def register(
        self,
        *,
        project_hash: str,
        workspace: str,
        project: str,
        servers: list[str],
        tools: dict[str, list[str]],
        remote_servers: dict[str, Any] | None = None,
        custom_servers: dict[str, Any] | None = None,
        server_network: dict[str, Any] | None = None,
    ) -> None:
        def dump(mapping: dict[str, Any] | None) -> dict[str, Any]:
            return {
                name: s.model_dump(mode="json") if hasattr(s, "model_dump") else s
                for name, s in (mapping or {}).items()
            }

        self.projects[project_hash] = {
            "workspace": workspace,
            "project": project,
            "servers": sorted(set(servers)),
            "tools": {k: sorted(set(v)) for k, v in tools.items()},
            "remote_servers": dump(remote_servers),
            "custom_servers": dump(custom_servers),
            "server_network": {
                name: getattr(mode, "value", str(mode))
                for name, mode in (server_network or {}).items()
            },
        }

    def forget(self, project_hash: str) -> None:
        self.projects.pop(project_hash, None)

    @property
    def servers(self) -> list[str]:
        out: set[str] = set()
        for entry in self.projects.values():
            out.update(entry.get("servers") or [])
        return sorted(out)

    def network_none(self) -> list[str]:
        """Servers any bound project wants on ``--network none``.

        Most-restrictive-wins. One gateway serves every project on the profile
        and a container has one network placement, so a disagreement has to
        resolve somehow; resolving it towards the narrower answer is the only
        direction that cannot quietly widen another project's sandbox.
        `network_conflicts` names the disagreements so the loser is not
        surprised.
        """
        out: set[str] = set()
        for entry in self.projects.values():
            out.update(
                name
                for name, mode in (entry.get("server_network") or {}).items()
                if mode == "none"
            )
        return sorted(out)

    def network_conflicts(self) -> list[str]:
        """Servers one project pins to `none` while another leaves shared."""
        restricted = set(self.network_none())
        out: set[str] = set()
        for entry in self.projects.values():
            declared = entry.get("server_network") or {}
            for name in entry.get("servers") or []:
                if name in restricted and declared.get(name) != "none":
                    out.add(name)
        return sorted(out)

    def remote_servers(self) -> dict[str, Any]:
        """Union of manifest-declared remote servers across bound projects.

        A later project redefining a name wins; `doctor` reports the conflict so
        it does not silently repoint another project's server.
        """
        from .manifest import RemoteServer

        out: dict[str, Any] = {}
        for entry in self.projects.values():
            for name, payload in (entry.get("remote_servers") or {}).items():
                out[name] = (
                    payload
                    if isinstance(payload, RemoteServer)
                    else RemoteServer.model_validate(payload)
                )
        return out

    def custom_servers(self) -> dict[str, Any]:
        """Union of custom-server definitions across projects on this profile."""
        from .manifest import CustomServer

        out: dict[str, Any] = {}
        for entry in self.projects.values():
            for name, payload in (entry.get("custom_servers") or {}).items():
                out[name] = (
                    payload
                    if isinstance(payload, CustomServer)
                    else CustomServer.model_validate(payload)
                )
        return out

    def remote_conflicts(self) -> list[str]:
        seen: dict[str, str] = {}
        clashes: list[str] = []
        for entry in self.projects.values():
            for name, payload in (entry.get("remote_servers") or {}).items():
                url = (
                    payload.get("url")
                    if isinstance(payload, dict)
                    else getattr(payload, "url", "")
                )
                if name in seen and seen[name] != url:
                    clashes.append(name)
                seen[name] = url
        return sorted(set(clashes))

    def tool_conflicts(self) -> dict[str, list[str]]:
        """Servers whose declared narrowing this profile cannot enforce.

        Maps the server to the projects that use it **unfiltered** — the reason
        the narrowing was dropped, which is what an operator needs in order to
        do something about it. `network_conflicts` names disagreements for the
        opposite resolution; this is the same courtesy for the union.

        ``doctor`` fails on it: a narrowing that is enforced nowhere and
        reported nowhere is a permission boundary that exists only in the file
        the operator wrote.
        """
        narrowed: set[str] = set()
        unfiltered_by: dict[str, set[str]] = {}
        for entry in self.projects.values():
            filters = entry.get("tools") or {}
            project = str(entry.get("project") or "?")
            for name in entry.get("servers") or []:
                if name in filters:
                    narrowed.add(name)
                else:
                    unfiltered_by.setdefault(name, set()).add(project)
        return {
            name: sorted(projects)
            for name, projects in sorted(unfiltered_by.items())
            if name in narrowed
        }

    @property
    def tools(self) -> list[str]:
        """Union of per-server tool filters.

        A filter is only meaningful when *every* project that uses a server
        narrows it; if one project wants the whole server, the narrowing would
        silently break it, so the union wins.

        There is no compensating control at the agent. This docstring used to
        claim per-project narrowing was "the agent's ``.mcp.json`` job", and
        `mcp_config` renders a URL and a bearer token and nothing else — so a
        dropped filter was enforced precisely nowhere while reading as though it
        were handled elsewhere. `tool_conflicts` names what was dropped and
        `doctor` fails on it.
        """
        wanted: set[str] = set()
        narrowed: dict[str, set[str]] = {}
        unfiltered: set[str] = set()
        for entry in self.projects.values():
            servers = set(entry.get("servers") or [])
            filters = entry.get("tools") or {}
            wanted |= servers
            for name in servers:
                if name in filters:
                    narrowed.setdefault(name, set()).update(filters[name])
                else:
                    unfiltered.add(name)
        out: set[str] = set()
        for name, tools in narrowed.items():
            if name not in unfiltered:
                out |= tools
        return sorted(out)


@dataclass(frozen=True)
class KnownProject:
    """A project abox has seen, from the per-profile registries."""

    project: str
    profile: str
    workspace: Path

    @property
    def exists(self) -> bool:
        return (self.workspace / "agentbox.yaml").is_file()


def known_projects() -> list[KnownProject]:
    """Every project bound to any profile, newest registry first.

    This is how abox answers "who else can read this secret" — a question worth
    being able to answer before rotating or revoking one.
    """
    out: list[KnownProject] = []
    seen: set[Path] = set()
    for path in sorted(gateways_dir().glob("*.json")):
        profile = path.stem
        for entry in ProfileRegistry.load(profile).projects.values():
            workspace = Path(str(entry.get("workspace") or ""))
            if not str(workspace) or workspace in seen:
                continue
            seen.add(workspace)
            out.append(
                KnownProject(
                    project=str(entry.get("project") or workspace.name),
                    profile=profile,
                    workspace=workspace,
                )
            )
    return sorted(out, key=lambda p: p.project)


# -- container spec -------------------------------------------------------


#: Where the gateway container looks for catalogs. ``--additional-catalog``
#: takes a bare filename that must resolve under this directory.
CONTAINER_CATALOG_DIR = "/root/.docker/mcp/catalogs"


def abox_catalog_name(profile: str) -> str:
    return f"abox-{profile}.yaml"


def abox_catalog_path(profile: str) -> Path:
    return gateways_dir() / abox_catalog_name(profile)


#: Backwards-compatible aliases; the file now carries both kinds of server.
remote_catalog_name = abox_catalog_name
remote_catalog_path = abox_catalog_path


def rendered_catalog_sha(profile: str) -> str:
    """sha256 of the catalog file the gateway mounts, or "" when there is none.

    Hashed into the gateway fingerprint. The *rendered file* is the thing the
    container loads, and it carries content the spec does not model: a
    ``network: none`` shadow is a verbatim copy of the upstream catalog entry,
    image and all, so an upstream refresh (a CVE fix, say) changes what the
    gateway would spawn while the modelled ``network_none`` name list stays
    identical.
    """
    path = abox_catalog_path(profile)
    if not path.is_file():
        return ""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _network_none_shadows(
    names: Iterable[str],
    custom_servers: dict[str, Any],
    catalog: Catalog | None,
) -> dict[str, Any]:
    """Shadow entries that put catalog servers on ``--network none``.

    Custom servers are skipped: abox writes their entry itself, so the flag goes
    in directly rather than through a second entry that would then fight it.
    A name abox has no catalog entry for is skipped too — emitting a stub would
    replace a working server with a broken one, which is a worse failure than
    leaving it on the shared network and saying so.
    """
    out: dict[str, Any] = {}
    for name in sorted(set(names)):
        if name in custom_servers:
            continue
        entry = catalog.get(name) if catalog is not None else None
        if entry is None or not entry.raw or entry.is_remote:
            continue
        shadow = dict(entry.raw)
        shadow["disableNetwork"] = True
        # allowHosts and --network none are mutually exclusive: the gateway
        # would emit `--network none --network docker-mcp-proxies-int` and
        # Docker refuses to start the container at all.
        shadow.pop("allowHosts", None)
        out[name] = shadow
    return out


def write_abox_catalog(
    profile: str,
    remote_servers: dict[str, Any] | None = None,
    custom_servers: dict[str, Any] | None = None,
    network_none: Iterable[str] = (),
    catalog: Catalog | None = None,
) -> Path | None:
    """Render everything the stock catalog does not carry into one v3 catalog.

    The gateway only knows servers that appear in a catalog it can read, so this
    file is what makes two things work at all: internet-hosted servers (which it
    proxies, keeping the agent to one endpoint) and the operator's own images
    from ``custom-servers.yaml``.

    It is also where ``network: none`` lands. For a custom server abox writes
    the whole entry anyway, so the flag is one more key. For a *catalog* server
    abox does not own the entry, so it re-emits the upstream entry verbatim
    under the same key with ``disableNetwork: true`` added — catalogs merge by
    key and the later one wins. The gateway logs the overwrite by name, and
    doctor reports it, so it is not a silent substitution. The copy is taken
    from the catalog on every render, and the rendered file is hashed into the
    gateway fingerprint (`rendered_catalog_sha`), so a changed upstream entry
    recreates the container instead of leaving the running gateway spawning the
    image the copy used to name.
    """
    path = abox_catalog_path(profile)
    remote_servers = remote_servers or {}
    custom_servers = custom_servers or {}
    shadows = _network_none_shadows(network_none, custom_servers, catalog)
    if not remote_servers and not custom_servers and not shadows:
        path.unlink(missing_ok=True)
        return None

    registry: dict[str, Any] = dict(shadows)
    wanted_none = set(network_none)
    for name, server in sorted(custom_servers.items()):
        entry = server.catalog_entry(name)
        # A custom server can be pinned to `none` from either side: its own
        # `network:` in custom-servers.yaml, or a project's `server_network`.
        # The second one has to land here, because the shadow path deliberately
        # skips custom servers rather than emit a duplicate entry to fight this.
        if name in wanted_none:
            entry["disableNetwork"] = True
            entry.pop("allowHosts", None)
        registry[name] = entry

    for name, server in sorted(remote_servers.items()):
        transport = getattr(server, "transport", "")
        entry: dict[str, Any] = {
            "description": getattr(server, "description", "") or f"remote MCP server {name}",
            "title": name,
            "type": "remote",
            "remote": {
                "transport_type": getattr(transport, "value", str(transport)),
                "url": server.url,
            },
        }
        headers = dict(getattr(server, "headers", {}) or {})
        if headers:
            entry["remote"]["headers"] = headers
        secrets = list(getattr(server, "secrets", []) or [])
        if secrets:
            entry["secrets"] = [{"name": s.name, "env": s.env} for s in secrets]
        registry[name] = entry

    body = yaml.safe_dump(
        {
            "version": 3,
            "name": f"abox-{profile}",
            "displayName": f"abox servers ({profile})",
            "registry": registry,
        },
        sort_keys=False,
    )
    path.write_text("# Generated by abox — DO NOT EDIT.\n" + body, encoding="utf-8")
    path.chmod(0o600)
    return path


#: Retained so existing callers keep working.
write_remote_catalog = write_abox_catalog


def _parse_host_bind(spec: str) -> tuple[str, bool] | None:
    """``(host source, read_only)`` for a host-path bind, or ``None`` for a named
    volume.

    Mirrors the gateway's own split (``docker_binds.go``): a bare-name source is
    a Docker volume, not a host path, and needs no allow-listing.
    """
    parts = spec.split(":")
    if len(parts) < 2:
        return None
    source = parts[0].strip()
    if not source or not (source.startswith(("/", "~", ".")) or "/" in source):
        return None
    mode = parts[2].strip().lower() if len(parts) >= 3 else ""
    read_only = any(opt in ("ro", "readonly") for opt in mode.split(","))
    return source, read_only


def _bind_allow_paths(
    custom_servers: tuple[tuple[str, Any], ...],
) -> tuple[list[str], list[str]]:
    """Host paths the gateway must be told to trust for custom-server volumes.

    The gateway refuses host bind mounts outside its ``/tmp`` roots unless the
    exact path is allow-listed (``docker_binds.go``): read-only via
    ``MCP_GATEWAY_DOCKER_BIND_ALLOWED_PATHS``, writable via
    ``MCP_GATEWAY_DOCKER_BIND_ALLOW_WRITABLE_PATHS``. Returns ``(writable, ro)``,
    de-duplicated and sorted. A ``:ro`` volume lands in the read-only set, which
    keeps the gateway's own default — host binds are read-only unless a path is
    explicitly trusted for writing.
    """
    writable: list[str] = []
    readonly: list[str] = []
    for _name, server in custom_servers:
        volumes = getattr(server, "volumes", None)
        if volumes is None and isinstance(server, dict):
            volumes = server.get("volumes")
        for spec in volumes or []:
            parsed = _parse_host_bind(spec)
            if parsed is None:
                continue
            host, ro = parsed
            (readonly if ro else writable).append(host)
    return sorted(dict.fromkeys(writable)), sorted(dict.fromkeys(readonly))


@dataclass(frozen=True)
class GatewaySpec:
    profile: str
    container: str
    image: str
    port: int
    network: str
    servers: tuple[str, ...]
    tools: tuple[str, ...]
    token: str
    #: (name, RemoteServer) pairs the gateway proxies instead of running.
    remote_servers: tuple[tuple[str, Any], ...] = ()
    #: (name, CustomServer) pairs from custom-servers.yaml that the stock
    #: catalog does not carry, so the gateway needs them written out.
    custom_servers: tuple[tuple[str, Any], ...] = ()
    #: Servers to spawn with ``--network none``. Most-restrictive-wins across
    #: the projects bound to this profile: one gateway serves all of them, so a
    #: server cannot be on two networks at once, and the safe answer to a
    #: disagreement is the narrower one. doctor reports the disagreement.
    network_none: tuple[str, ...] = ()

    @property
    def url(self) -> str:
        return f"http://{self.container}:{self.port}/mcp"

    @property
    def remote_names(self) -> tuple[str, ...]:
        return tuple(name for name, _ in self.remote_servers)

    @property
    def custom_names(self) -> tuple[str, ...]:
        return tuple(name for name, _ in self.custom_servers)

    @property
    def needs_catalog(self) -> bool:
        return bool(self.remote_servers or self.custom_servers or self.network_none)

    @property
    def all_servers(self) -> tuple[str, ...]:
        return tuple(sorted({*self.servers, *self.remote_names, *self.custom_names}))

    def run_options(self) -> list[str]:
        """``docker run`` options — deliberately no ``-p``: nothing is published."""
        opts = [
            "--network",
            self.network,
            "--restart",
            "unless-stopped",
            "--label",
            f"{dockerx.LABEL_MANAGED}=true",
            "--label",
            f"{dockerx.LABEL_ROLE}=gateway",
            "--label",
            f"{dockerx.LABEL_PROFILE}={self.profile}",
            "-e",
            f"MCP_GATEWAY_AUTH_TOKEN={self.token}",
            "-v",
            "/var/run/docker.sock:/var/run/docker.sock",
        ]
        # A custom-server volume that binds a host path outside the gateway's
        # default /tmp roots is refused unless we name it here. `:` is the
        # gateway's list separator (it always runs on Linux); writable access
        # needs the exact path, read-only a trusted path or parent.
        writable, readonly = _bind_allow_paths(self.custom_servers)
        if writable:
            opts += [
                "-e",
                "MCP_GATEWAY_DOCKER_BIND_ALLOW_WRITABLE_PATHS=" + ":".join(writable),
            ]
        if readonly:
            opts += [
                "-e",
                "MCP_GATEWAY_DOCKER_BIND_ALLOWED_PATHS=" + ":".join(readonly),
            ]
        if self.needs_catalog:
            host_path = abox_catalog_path(self.profile)
            opts += [
                "-v",
                f"{host_path}:{CONTAINER_CATALOG_DIR}/{abox_catalog_name(self.profile)}:ro",
            ]
        return opts

    def gateway_args(self) -> list[str]:
        args = [
            "--transport=streaming",
            f"--port={self.port}",
            "--host=0.0.0.0",
            "--verify-signatures",
            "--log-calls",
            "--block-secrets",
            "--secrets=docker-desktop",
        ]
        if self.needs_catalog:
            args.append(f"--additional-catalog={abox_catalog_name(self.profile)}")
        if self.all_servers:
            args.append("--servers=" + ",".join(self.all_servers))
        if self.tools:
            args.append("--tools=" + ",".join(self.tools))
        return args

    def fingerprint(self) -> str:
        """Everything that, if changed, means the container must be recreated.

        Includes the derived bind-allow paths, so adding a custom-server volume
        recreates the gateway — the run options that carry the new
        ``MCP_GATEWAY_DOCKER_BIND_*`` env are not otherwise part of this hash.
        """
        writable, readonly = _bind_allow_paths(self.custom_servers)
        return json.dumps(
            {
                "image": self.image,
                "port": self.port,
                "network": self.network,
                "servers": list(self.servers),
                "tools": list(self.tools),
                "bind_writable": writable,
                "bind_ro": readonly,
                # The catalog the gateway reads is written at `up` time and only
                # re-read on start, so a changed network placement must recreate
                # the container or the old catalog keeps serving.
                "network_none": list(self.network_none),
                # ...and the same is true of what is *in* those entries, which the
                # name list above does not capture: a refreshed upstream image
                # rewrites the file without changing any name here.
                "catalog": rendered_catalog_sha(self.profile),
                "custom": {
                    name: server.model_dump(mode="json")
                    if hasattr(server, "model_dump")
                    else str(server)
                    for name, server in self.custom_servers
                },
                "remote": {
                    name: {
                        "url": server.url,
                        "transport": str(
                            getattr(getattr(server, "transport", ""), "value", "")
                        ),
                        "headers": dict(getattr(server, "headers", {}) or {}),
                    }
                    for name, server in self.remote_servers
                },
            },
            sort_keys=True,
        )


def build_spec(
    profile: str,
    config: GlobalConfig,
    *,
    servers: list[str],
    tools: list[str] | None = None,
    image: str | None = None,
    remote_servers: dict[str, Any] | None = None,
    custom_servers: dict[str, Any] | None = None,
    network_none: Iterable[str] = (),
) -> GatewaySpec:
    profile_cfg = config.profile(profile)
    custom = custom_servers or {}
    # A custom server declaring `network: none` needs no separate opt-in: the
    # declaration is the opt-in, and its entry already carries the flag.
    from .manifest import ServerNetwork

    declared_none = {
        name
        for name, server in custom.items()
        if getattr(server, "network", ServerNetwork.shared) is ServerNetwork.none
    }
    return GatewaySpec(
        profile=profile,
        container=paths.gateway_container(profile),
        image=image or config.gateway_image,
        port=profile_cfg.port,
        network=config.network,
        servers=tuple(sorted(set(servers))),
        tools=tuple(sorted(set(tools or []))),
        token=ensure_token(profile),
        remote_servers=tuple(sorted((remote_servers or {}).items())),
        custom_servers=tuple(sorted(custom.items())),
        network_none=tuple(sorted(set(network_none) | declared_none)),
    )


def spec_from_registry(
    profile: str,
    config: GlobalConfig,
    registry: ProfileRegistry,
    *,
    servers: list[str] | None = None,
    tools: list[str] | None = None,
    remote_servers: dict[str, Any] | None = None,
    custom_servers: dict[str, Any] | None = None,
    network_none: Iterable[str] | None = None,
) -> GatewaySpec:
    """What the profile's registry asks for, with optional caller overrides.

    `up` and `status` must build this the same way: they compare fingerprints
    with each other, so a field one of them forgets is permanent drift. That is
    what happened to ``network_none`` — `status` omitted it, `doctor` turned
    every run into a `gateway.drift` warning, and `abox gateway up --force`
    re-stored the same mismatching value without clearing it. A warning that
    fires unconditionally hides the stale gateway it exists to catch.
    """
    return build_spec(
        profile,
        config,
        servers=servers if servers is not None else registry.servers,
        tools=tools if tools is not None else registry.tools,
        remote_servers=(
            remote_servers if remote_servers is not None else registry.remote_servers()
        ),
        custom_servers=(
            custom_servers if custom_servers is not None else registry.custom_servers()
        ),
        network_none=(
            network_none if network_none is not None else registry.network_none()
        ),
    )


# -- health probing -------------------------------------------------------

_PROBE_SCRIPT = r"""
set -e
URL="$1"; TOKEN="$2"; MODE="$3"
PROTO='%(proto)s'
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":'
INIT="${INIT}"'{"protocolVersion":"'"${PROTO}"'","capabilities":{},'
INIT="${INIT}"'"clientInfo":{"name":"abox-probe","version":"1"}}}'
HDRS="--header=Content-Type: application/json"
resp=$(busybox wget -q -S -O - -T 10 \
  --header="Content-Type: application/json" \
  --header="Accept: application/json, text/event-stream" \
  --header="Authorization: Bearer $TOKEN" \
  --post-data="$INIT" "$URL" 2>&1)
echo "$resp" | grep -q '"serverInfo"' || { echo "$resp"; exit 21; }
# Always emit the initialize response: the caller parses it to confirm the
# handshake actually happened, in tools mode as well as health mode.
echo "$resp"
if [ "$MODE" != "tools" ]; then exit 0; fi
SID=$(echo "$resp" | tr -d '\r' | grep -i 'Mcp-Session-Id:' | head -1 | sed 's/.*[Ii][Dd]: *//')
busybox wget -q -O - -T 10 \
  --header="Content-Type: application/json" \
  --header="Accept: application/json, text/event-stream" \
  --header="Authorization: Bearer $TOKEN" \
  --header="Mcp-Session-Id: $SID" \
  --post-data='{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  "$URL" >/dev/null 2>&1 || true
busybox wget -q -O - -T 15 \
  --header="Content-Type: application/json" \
  --header="Accept: application/json, text/event-stream" \
  --header="Authorization: Bearer $TOKEN" \
  --header="Mcp-Session-Id: $SID" \
  --post-data='{"jsonrpc":"2.0","id":2,"method":"tools/list"}' "$URL"
""".replace("%(proto)s", MCP_PROTOCOL_VERSION)


@dataclass(frozen=True)
class ProbeResult:
    ok: bool
    detail: str
    server_info: dict[str, Any] | None = None
    tools: tuple[str, ...] = ()
    #: Full tool objects as the agent receives them, for cost accounting.
    tool_schemas: tuple[dict[str, Any], ...] = ()


def _parse_sse(payload: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in payload.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        try:
            out.append(json.loads(line[5:].strip()))
        except json.JSONDecodeError:
            continue
    return out


def probe(spec: GatewaySpec, *, want_tools: bool = False, timeout: int = 60) -> ProbeResult:
    """Speak MCP to the gateway from a throwaway container on the same bridge.

    This is the only honest health check: it proves the exact path the agent
    will take (container DNS name, port, bearer token, ``/mcp`` endpoint),
    not merely that a process is up.
    """
    argv = [
        "run",
        "--rm",
        "--network",
        spec.network,
        "--label",
        f"{dockerx.LABEL_MANAGED}=true",
        "--label",
        f"{dockerx.LABEL_ROLE}=probe",
        "--entrypoint",
        "/bin/sh",
        spec.image,
        "-c",
        _PROBE_SCRIPT,
        "abox-probe",
        spec.url,
        spec.token,
        "tools" if want_tools else "health",
    ]
    result = dockerx.docker(*argv, timeout=timeout)
    payload = result.stdout + result.stderr
    if not result.ok and "serverInfo" not in payload:
        detail = payload.strip().splitlines()
        return ProbeResult(False, detail[-1] if detail else "probe failed")

    messages = _parse_sse(payload)
    server_info: dict[str, Any] | None = None
    tools: list[str] = []
    schemas: list[dict[str, Any]] = []
    for msg in messages:
        res = msg.get("result") or {}
        if "serverInfo" in res:
            server_info = res["serverInfo"]
        for tool in res.get("tools") or []:
            name = tool.get("name")
            if name:
                tools.append(name)
                schemas.append(tool)
    if server_info is None:
        return ProbeResult(False, "gateway did not complete an MCP initialize handshake")
    name = server_info.get("name", "gateway")
    version = server_info.get("version", "?")
    return ProbeResult(
        True, f"{name} {version}", server_info, tuple(tools), tuple(schemas)
    )


# -- lifecycle ------------------------------------------------------------


@dataclass(frozen=True)
class GatewayStatus:
    profile: str
    container: str
    exists: bool
    running: bool
    healthy: bool
    detail: str
    url: str = ""
    image: str = ""
    servers: tuple[str, ...] = ()
    remote_servers: tuple[str, ...] = ()
    published_ports: tuple[str, ...] = ()
    fingerprint_matches: bool = True

    @property
    def ok(self) -> bool:
        return self.running and self.healthy


def _stored_fingerprint(profile: str) -> str | None:
    path = gateways_dir() / f"{profile}.fingerprint"
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8").strip()


def _store_fingerprint(profile: str, value: str) -> None:
    path = gateways_dir() / f"{profile}.fingerprint"
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)


def ensure_server_images(spec: GatewaySpec, catalog: Catalog) -> list[str]:
    """Pre-pull MCP server images.

    The gateway spawns servers with ``--pull never``; without this step the
    first tool call fails with a bare "No such image" deep in the gateway log.
    """
    pulled: list[str] = []
    for name in spec.servers:
        server = catalog.get(name)
        if server is None or not server.image:
            continue
        if dockerx.image_present(server.image):
            continue
        if getattr(server, "local_image", False):
            # `pin: false` — a local image abox must not pull. If it is not on
            # the daemon there is nothing to fetch, so say so plainly rather than
            # attempt a doomed `docker pull` of a tag that lives in no registry.
            raise GatewayError(
                f"local image {server.image!r} for server {name!r} is not present",
                hint="it is declared `pin: false`, so abox will not pull it — "
                f"build or load it first (e.g. `docker build -t {server.image} .`)",
            )
        result = dockerx.pull(server.image)
        if result.ok:
            pulled.append(server.image)
        else:
            detail = (result.stderr or result.stdout).strip().splitlines()
            raise GatewayError(
                f"could not pull MCP server image for {name!r}: "
                f"{detail[-1] if detail else 'unknown error'}",
                hint="the gateway starts servers with --pull never, so the image "
                "must be present on the daemon before the first tool call",
            )
    return pulled


def status(profile: str, config: GlobalConfig, *, deep: bool = True) -> GatewayStatus:
    container = paths.gateway_container(profile)
    state = dockerx.container_state(container)
    registry = ProfileRegistry.load(profile)
    token = read_token(profile)
    if not state.exists:
        return GatewayStatus(
            profile=profile,
            container=container,
            exists=False,
            running=False,
            healthy=False,
            detail="not created",
        )
    spec = spec_from_registry(profile, config, registry)
    if not state.running:
        return GatewayStatus(
            profile=profile,
            container=container,
            exists=True,
            running=False,
            healthy=False,
            detail=f"container {state.status}",
            image=state.image,
            servers=spec.all_servers,
            published_ports=tuple(state.published_ports),
        )
    healthy, detail = False, "not probed"
    if deep and token:
        result = probe(spec)
        healthy, detail = result.ok, result.detail
    elif not token:
        detail = "no gateway token on file — recreate with `abox gateway up`"
    stored = _stored_fingerprint(profile)
    return GatewayStatus(
        profile=profile,
        container=container,
        exists=True,
        running=True,
        healthy=healthy,
        detail=detail,
        url=spec.url,
        image=state.image,
        servers=spec.all_servers,
        remote_servers=spec.remote_names,
        published_ports=tuple(state.published_ports),
        fingerprint_matches=stored is None or stored == spec.fingerprint(),
    )


def up(
    profile: str,
    config: GlobalConfig,
    catalog: Catalog,
    *,
    servers: list[str] | None = None,
    tools: list[str] | None = None,
    remote_servers: dict[str, Any] | None = None,
    custom_servers: dict[str, Any] | None = None,
    network_none: Iterable[str] | None = None,
    force: bool = False,
    pull_images: bool = True,
) -> GatewayStatus:
    """Bring the profile's gateway to the desired state, recreating on drift."""
    registry = ProfileRegistry.load(profile)
    spec = spec_from_registry(
        profile,
        config,
        registry,
        servers=servers,
        tools=tools,
        remote_servers=remote_servers,
        custom_servers=custom_servers,
        network_none=network_none,
    )

    # Rendered before the fingerprint is taken, because the fingerprint hashes
    # the rendered file.
    write_abox_catalog(
        profile,
        dict(spec.remote_servers),
        dict(spec.custom_servers),
        spec.network_none,
        catalog,
    )
    dockerx.ensure_network(spec.network)
    if pull_images:
        ensure_server_images(spec, catalog)

    state = dockerx.container_state(spec.container)
    drifted = _stored_fingerprint(profile) != spec.fingerprint()
    if state.exists and (force or drifted or not state.running):
        dockerx.remove(spec.container)
        state = dockerx.container_state(spec.container)

    if not state.exists:
        if not dockerx.image_present(spec.image):
            pull = dockerx.pull(spec.image)
            if not pull.ok:
                raise GatewayError(
                    f"could not pull gateway image {spec.image}: "
                    f"{pull.stderr.strip()[:200]}",
                )
        dockerx.run_detached(
            spec.container, spec.image, spec.gateway_args(), opts=spec.run_options()
        )
        _store_fingerprint(profile, spec.fingerprint())

    result = _wait_healthy(spec)
    if not result.ok:
        logs = dockerx.logs(spec.container, tail=30)
        raise GatewayError(
            f"gateway {spec.container} did not become healthy: {result.detail}",
            hint=f"`docker logs {spec.container}` tail:\n{logs[-1500:]}",
        )
    current = status(profile, config, deep=False)
    return replace(current, healthy=True, detail=result.detail, url=spec.url)


def _wait_healthy(spec: GatewaySpec, *, attempts: int = 6) -> ProbeResult:
    last = ProbeResult(False, "never probed")
    for _ in range(attempts):
        last = probe(spec)
        if last.ok:
            return last
    return last


def down(profile: str, *, remove: bool = True) -> bool:
    container = paths.gateway_container(profile)
    state = dockerx.container_state(container)
    if not state.exists:
        return False
    if state.running:
        dockerx.stop(container)
    if remove:
        dockerx.remove(container)
    return True


def bind_project(
    profile: str,
    *,
    workspace: Path,
    project: str,
    servers: list[str],
    tools: dict[str, list[str]],
    remote_servers: dict[str, Any] | None = None,
    custom_servers: dict[str, Any] | None = None,
    server_network: dict[str, Any] | None = None,
) -> ProfileRegistry:
    """Record this project's demands on the shared profile gateway."""
    registry = ProfileRegistry.load(profile)
    registry.register(
        project_hash=paths.project_hash(workspace),
        workspace=str(workspace),
        project=project,
        servers=servers,
        tools=tools,
        remote_servers=remote_servers,
        custom_servers=custom_servers,
        server_network=server_network,
    )
    registry.save()
    return registry


def unbind_project(profile: str, workspace: Path) -> ProfileRegistry:
    registry = ProfileRegistry.load(profile)
    registry.forget(paths.project_hash(workspace))
    registry.save()
    return registry


def mcp_config(spec: GatewaySpec, *, server_name: str = "abox-gateway") -> dict[str, Any]:
    """The ``.mcp.json`` fragment handed to Claude Code inside the container."""
    return {
        "mcpServers": {
            server_name: {
                "type": "http",
                "url": spec.url,
                "headers": {"Authorization": f"Bearer {spec.token}"},
            }
        }
    }


#: Rough characters-per-token for English + JSON. Good enough to rank servers
#: by cost, which is all this is for; it is not a billing figure.
CHARS_PER_TOKEN = 4


#: Bucket for tools no catalog entry claims. Never a server name.
UNATTRIBUTED = "\x00unattributed"


def attribute_tools(
    schemas: Iterable[dict[str, Any]], catalog: Any, servers: Iterable[str]
) -> dict[str, list[dict[str, Any]]]:
    """Group live tool schemas by the server that declares them.

    The gateway's ``tools/list`` is flat and carries no server field, so
    attribution comes from catalog metadata. That covers Docker catalog servers
    — which is where the cost concentrates — but not a custom image or a remote
    URL whose tool names abox has never been told. Those land under
    ``UNKNOWN`` rather than being guessed into the wrong bucket.
    """
    owner_of: dict[str, str] = {}
    for name in servers:
        entry = catalog.get(name) if catalog is not None else None
        for tool in getattr(entry, "tools", ()) or ():
            owner_of[tool] = name
    grouped: dict[str, list[dict[str, Any]]] = {}
    for schema in schemas:
        tool = str(schema.get("name", ""))
        grouped.setdefault(owner_of.get(tool, UNATTRIBUTED), []).append(schema)
    return grouped


def tool_schema_cost(schemas: Iterable[dict[str, Any]]) -> int:
    """Approximate tokens the agent spends carrying these tool definitions.

    Tool schemas are re-sent every turn, so this is a per-turn tax, not a
    one-off — which is what makes narrowing worth the bother.
    """
    payload = json.dumps(list(schemas), separators=(",", ":"))
    return len(payload) // CHARS_PER_TOKEN


def sanitize_for_log(text: str, *, profile: str | None = None) -> str:
    """Redact any gateway token that made it into text destined for a log."""
    tokens = []
    if profile:
        if tok := read_token(profile):
            tokens.append(tok)
    else:
        for path in gateways_dir().glob("*.token"):
            value = path.read_text(encoding="utf-8").strip()
            if value:
                tokens.append(value)
    for token in tokens:
        text = text.replace(token, "«gateway-token»")
    return re.sub(r"(?i)(authorization:\s*bearer\s+)\S+", r"\1«redacted»", text)


__all__ = [
    "GatewaySpec",
    "GatewayStatus",
    "ProbeResult",
    "ProfileRegistry",
    "bind_project",
    "build_spec",
    "down",
    "ensure_server_images",
    "ensure_token",
    "mcp_config",
    "probe",
    "remote_catalog_path",
    "rendered_catalog_sha",
    "sanitize_for_log",
    "spec_from_registry",
    "status",
    "unbind_project",
    "up",
    "write_remote_catalog",
]
