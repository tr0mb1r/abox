"""Read the Docker MCP catalog and the operator's custom-server registry.

Docker Desktop maintains a v3 catalog at ``~/.docker/mcp/catalogs/*.yaml`` whose
``registry:`` keys are exactly the names ``docker mcp gateway run --servers``
accepts. That file is the primary source: it is local, fast, and already
digest-pinned. The OCI catalog (``docker mcp catalog show``) is the fallback for
hosts where the local file has not been materialised yet — its entries are less
regular, so names are derived from the image reference there.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import shell
from .errors import AboxError
from .manifest import CustomServers

DEFAULT_CATALOG_REF = "mcp/docker-mcp-catalog:latest"


def catalog_dir() -> Path:
    if override := os.environ.get("ABOX_DOCKER_MCP_HOME"):
        return Path(override).expanduser() / "catalogs"
    return Path.home() / ".docker" / "mcp" / "catalogs"


@dataclass(frozen=True)
class CatalogServer:
    """One MCP server as abox needs to know it."""

    name: str
    title: str = ""
    description: str = ""
    image: str = ""
    #: Docker secret names the server expects (``github.personal_access_token``).
    secrets: tuple[str, ...] = ()
    tools: tuple[str, ...] = ()
    #: Hosts the catalog says the server talks to. **Informational only, and not
    #: a control.** The gateway's allowHosts machinery only constrains anything
    #: when the gateway itself sits on an internal network; on abox's topology
    #: it merely adds a proxy alongside the server's existing unrestricted
    #: network, and was empirically bypassed. `server_network: none` is the
    #: setting Docker actually enforces.
    allow_hosts: tuple[str, ...] = ()
    source: str = "catalog"
    #: Set for ``type: remote`` entries — the gateway proxies these over the
    #: internet instead of running a container, so there is no image to pin.
    remote_url: str = ""
    remote_transport: str = ""
    #: Catalog entry type: "server" (image), "remote" (URL), or "poci" — the
    #: last being an entry Docker resolves and builds at run time, with no image
    #: reference in the catalog to pin.
    kind: str = "server"
    #: OAuth providers the Docker MCP toolkit can authorise host-side.
    oauth_providers: tuple[str, ...] = ()
    #: True only for a custom server declared ``pin: false`` — a local image the
    #: operator built that abox must not pull and cannot integrity-check. The
    #: computed ``pinned`` property below reports it unpinned regardless; this is
    #: the narrower "do not pull, require local presence" intent, and it stays
    #: False for an ordinary unpinned *catalog* tag, which abox still pulls.
    local_image: bool = False
    #: The catalog entry exactly as read. Kept so abox can *shadow* an entry —
    #: re-emit it under the same key with one field added — without hand-copying
    #: a spec that would then drift. It is re-read on every render, so the copy
    #: is never older than the last `abox up`.
    raw: dict = field(default_factory=dict, compare=False, repr=False)

    @property
    def is_remote(self) -> bool:
        return bool(self.remote_url)

    @property
    def is_poci(self) -> bool:
        return self.kind == "poci"

    @property
    def pinned(self) -> bool:
        """Digest-pinned, or remote (in which case there is nothing to pin).

        Remote servers trade image pinning for a different trust story: the
        third party can change behaviour under you at any time. ``doctor``
        reports them separately rather than pretending a URL is pinned.
        """
        return self.is_remote or self.is_poci or "@sha256:" in self.image

    @property
    def label(self) -> str:
        return self.title or self.name

    def summary(self, width: int = 60) -> str:
        text = self.description.strip().replace("\n", " ")
        if len(text) > width:
            text = text[: width - 1].rstrip() + "…"
        return text


@dataclass
class Catalog:
    """All servers abox can offer: the Docker catalog plus the custom registry."""

    servers: dict[str, CatalogServer] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    #: Names defined by more than one catalog *file*, in load order — the last
    #: wins. Not the same as the custom-server overlay, which the operator wrote
    #: deliberately: these files land in ~/.docker/mcp/catalogs/ via
    #: `docker mcp catalog import`, so a collision here is a substitution the
    #: operator never asked for. `doctor` fails on it for a declared server.
    shadowed: dict[str, list[str]] = field(default_factory=dict)

    def __contains__(self, name: object) -> bool:
        return name in self.servers

    def get(self, name: str) -> CatalogServer | None:
        return self.servers.get(name)

    def require(self, name: str) -> CatalogServer:
        server = self.servers.get(name)
        if server is None:
            raise AboxError(
                f"unknown MCP server: {name!r}",
                hint="run `abox mcp list` to see the catalog, or declare it in "
                "~/.config/abox/custom-servers.yaml",
            )
        return server

    def names(self) -> list[str]:
        return sorted(self.servers)

    def secrets_for(self, names: Iterable[str]) -> list[str]:
        out: list[str] = []
        for name in names:
            server = self.servers.get(name)
            if server is None:
                continue
            for secret in server.secrets:
                if secret not in out:
                    out.append(secret)
        return out


def _parse_v3_registry(data: dict, source: str) -> dict[str, CatalogServer]:
    registry = data.get("registry") or {}
    out: dict[str, CatalogServer] = {}
    for name, entry in registry.items():
        if not isinstance(entry, dict):
            continue
        secrets = tuple(
            s["name"] for s in (entry.get("secrets") or []) if isinstance(s, dict) and "name" in s
        )
        tools = tuple(
            t["name"] for t in (entry.get("tools") or []) if isinstance(t, dict) and "name" in t
        )
        remote = entry.get("remote") or {}
        oauth = entry.get("oauth") or {}
        providers = tuple(
            p["provider"]
            for p in (oauth.get("providers") or [])
            if isinstance(p, dict) and "provider" in p
        )
        out[name] = CatalogServer(
            name=name,
            title=str(entry.get("title") or ""),
            description=str(entry.get("description") or ""),
            image=str(entry.get("image") or ""),
            secrets=secrets,
            tools=tools,
            allow_hosts=tuple(entry.get("allowHosts") or ()),
            source=source,
            remote_url=str(remote.get("url") or ""),
            remote_transport=str(remote.get("transport_type") or ""),
            oauth_providers=providers,
            kind=str(entry.get("type") or "server"),
            raw=dict(entry),
        )
    return out


def load_local_catalogs() -> tuple[dict[str, CatalogServer], list[str], dict[str, list[str]]]:
    """Parse every ``registry:``-shaped yaml under the Docker MCP catalog dir.

    Files are merged in filename order and a later one wins, which is fine as a
    rule and was silent as a behaviour. ``~/.docker/mcp/catalogs/`` is where
    ``docker mcp catalog import <url>`` puts third-party content, so a file that
    sorts after ``docker-mcp`` can redefine ``github-official`` to point at any
    image it likes — and every downstream control still passes, because
    ``servers.pinned`` is satisfied by the attacker's own digest.

    The third return value records every name defined more than once, in load
    order, so the winner is the last entry. abox already warns for the two other
    shadowing directions (custom-over-catalog here, manifest-remote-over-catalog
    in ``doctor``); this is the one that nobody authored deliberately.
    """
    servers: dict[str, CatalogServer] = {}
    warnings: list[str] = []
    origins: dict[str, list[str]] = {}
    directory = catalog_dir()
    if not directory.is_dir():
        return servers, [f"no Docker MCP catalog dir at {directory}"], {}
    for path in sorted(directory.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            warnings.append(f"skipped {path.name}: {exc}")
            continue
        if not isinstance(data, dict) or "registry" not in data:
            continue
        parsed = _parse_v3_registry(data, source=path.stem)
        for name in parsed:
            origins.setdefault(name, []).append(path.stem)
        servers.update(parsed)
    shadowed = {name: files for name, files in origins.items() if len(files) > 1}
    for name, files in sorted(shadowed.items()):
        warnings.append(
            f"catalog entry {name!r} is defined in {', '.join(files)} — "
            f"{files[-1]} wins"
        )
    if not servers:
        warnings.append(f"no catalog entries found under {directory}")
    return servers, warnings, shadowed


def load_oci_catalog(ref: str = DEFAULT_CATALOG_REF) -> tuple[dict[str, CatalogServer], list[str]]:
    """Fallback: ask the Docker CLI for the OCI catalog.

    Entries there carry a display name rather than the registry key, so the key
    is derived from the image repository — the same convention Docker uses when
    it materialises the local catalog.
    """
    warnings: list[str] = []
    result = shell.run(
        ["docker", "mcp", "catalog", "show", ref, "--format", "json", "--pull", "missing"],
        timeout=180,
    )
    if not result.ok:
        return {}, [f"docker mcp catalog show {ref} failed: {result.stderr.strip()[:200]}"]
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return {}, [f"catalog JSON from docker was unparseable: {exc}"]

    servers: dict[str, CatalogServer] = {}
    for entry in payload.get("servers") or []:
        snapshot = (entry or {}).get("snapshot") or {}
        server = snapshot.get("server") or {}
        image = str(entry.get("image") or server.get("image") or "")
        if not image:
            continue
        repo = image.split("@", 1)[0].split(":", 1)[0]
        name = repo.rsplit("/", 1)[-1]
        secrets = tuple(
            s["name"] for s in (server.get("secrets") or []) if isinstance(s, dict) and "name" in s
        )
        tools = tuple(
            t["name"] for t in (server.get("tools") or []) if isinstance(t, dict) and "name" in t
        )
        servers[name] = CatalogServer(
            name=name,
            title=str(server.get("title") or ""),
            description=str(server.get("description") or ""),
            image=image,
            secrets=secrets,
            tools=tools,
            allow_hosts=tuple(server.get("allowHosts") or ()),
            source="oci",
        )
    if not servers:
        warnings.append(f"OCI catalog {ref} yielded no usable servers")
    return servers, warnings


def remote_to_catalog(remote_servers: dict[str, object]) -> dict[str, CatalogServer]:
    """Present manifest-declared remote servers alongside catalog entries."""
    out: dict[str, CatalogServer] = {}
    for name, server in remote_servers.items():
        url = getattr(server, "url", "")
        transport = getattr(server, "transport", "")
        out[name] = CatalogServer(
            name=name,
            title=name,
            description=getattr(server, "description", "") or "remote server",
            secrets=tuple(s.name for s in getattr(server, "secrets", ()) or ()),
            source="manifest-remote",
            remote_url=str(url),
            remote_transport=str(getattr(transport, "value", transport)),
        )
    return out


def custom_to_catalog(custom: CustomServers) -> dict[str, CatalogServer]:
    out: dict[str, CatalogServer] = {}
    for name, server in custom.servers.items():
        out[name] = CatalogServer(
            name=name,
            title=name,
            description=server.description or "custom server",
            image=server.image,
            tools=() if server.all_tools else tuple(server.tools),
            # `CustomServer.secrets` holds ServerSecret models; this field holds
            # *names*. Passing the models through meant every consumer of
            # `secrets_for` — doctor's missing-secret list, `abox mcp ls`, the
            # init picker's getpass prompt — compared a model against a string
            # and then tried to join it into a message.
            secrets=tuple(s.name for s in server.secrets),
            source="custom",
            local_image=not server.pin,
        )
    return out


def load(
    *,
    custom: CustomServers | None = None,
    allow_oci_fallback: bool = True,
) -> Catalog:
    """Load the merged catalog. Custom servers win on name collision."""
    servers, warnings, cross_file = load_local_catalogs()
    if not servers and allow_oci_fallback:
        oci, oci_warnings = load_oci_catalog()
        servers, warnings, cross_file = oci, [*warnings, *oci_warnings], {}
    custom = custom if custom is not None else CustomServers.load()
    for name, why in sorted(getattr(custom, "rejected", {}).items()):
        # Dropped by CustomServers.load rather than raised, so one bad entry in
        # a global file cannot break every project on the host. Naming it here
        # is what keeps "dropped" from meaning "silently gone".
        warnings.append(f"custom server {name!r} was skipped — {why}")
    overlay = custom_to_catalog(custom)
    shadowed = sorted(set(overlay) & set(servers))
    for name in shadowed:
        warnings.append(f"custom server {name!r} shadows the catalog entry of the same name")
    servers.update(overlay)
    # A custom entry the operator wrote themselves is the last word, and it is
    # already reported above — so it settles the collision rather than leaving
    # the imported file to be blamed for a name it no longer supplies.
    return Catalog(
        servers=servers,
        warnings=warnings,
        shadowed={k: v for k, v in cross_file.items() if k not in overlay},
    )


# -- host inventory --------------------------------------------------------


@dataclass(frozen=True)
class HostServer:
    """An MCP server configured on the host, and whether abox can bring it in."""

    name: str
    source: str
    detail: str
    importable: bool
    reason: str = ""


def docker_mcp_registry() -> list[str]:
    """Servers enabled in the host's Docker MCP Toolkit (``registry.yaml``)."""
    path = catalog_dir().parent / "registry.yaml"
    if not path.is_file():
        return []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return []
    return sorted((data.get("registry") or {}).keys())


def claude_code_servers() -> dict[str, dict]:
    """User-scope MCP servers from the host's ``~/.claude.json``.

    Read-only and name-only: the file also holds project history and tokens, so
    nothing beyond the server name and transport is taken from it.
    """
    path = Path.home() / ".claude.json"
    if override := os.environ.get("ABOX_CLAUDE_CONFIG"):
        path = Path(override).expanduser()
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    out: dict[str, dict] = {}
    for name, cfg in (data.get("mcpServers") or {}).items():
        if not isinstance(cfg, dict):
            continue
        out[name] = {
            "type": cfg.get("type") or ("stdio" if cfg.get("command") else "unknown"),
            "command": str(cfg.get("command") or ""),
            "url": str(cfg.get("url") or ""),
        }
    return out


#: Host stdio servers that are really the Docker MCP gateway under another name.
#: Importing "MCP_DOCKER" itself would be meaningless — abox *is* that gateway.
_GATEWAY_COMMANDS = {"docker"}


def host_inventory(catalog: Catalog) -> list[HostServer]:
    """What the host has configured, and how each thing can reach the sandbox."""
    out: list[HostServer] = []

    for name in docker_mcp_registry():
        entry = catalog.get(name)
        if entry is None:
            out.append(
                HostServer(
                    name, "docker-mcp", "enabled in the Docker MCP Toolkit", False,
                    "not present in the catalog abox can see",
                )
            )
            continue
        kind = "remote" if entry.is_remote else ("poci" if entry.is_poci else "image")
        out.append(
            HostServer(name, "docker-mcp", f"catalog {kind} server", True)
        )

    for name, cfg in claude_code_servers().items():
        if cfg["command"] in _GATEWAY_COMMANDS:
            out.append(
                HostServer(
                    name, "claude-code", "the Docker MCP gateway in stdio mode", False,
                    "abox already is this gateway — import its servers instead",
                )
            )
        elif cfg["url"]:
            out.append(
                HostServer(
                    name, "claude-code", f"remote {cfg['url']}", True,
                    "add with `abox mcp add-remote`",
                )
            )
        else:
            out.append(
                HostServer(
                    name, "claude-code", f"local stdio process ({cfg['command']})", False,
                    "a host binary; running it for the agent would mean mounting it "
                    "and its data into the sandbox",
                )
            )
    return out
