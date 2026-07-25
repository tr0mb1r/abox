"""``abox doctor`` — the audit that decides whether a run may claim its sandbox.

Every check answers one question with evidence from the machine, not from the
manifest's own claims. The distinction matters most for check 6: the manifest
asking for ``bypassPermissions`` is precisely the situation in which its word is
worth least, so that check reads the rendered container config instead.
"""

from __future__ import annotations

import configparser
import hashlib
import json
import os
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from . import dockerx, gateway, paths, render, secrets, shell, telemetry
from .catalog import Catalog
from .errors import AboxError
from .manifest import (
    CustomServers,
    GlobalConfig,
    Manifest,
    PermissionMode,
    SecretsConfig,
    effective_allowlist,
    merged_egress,
    merged_watch,
)


class Status(StrEnum):
    ok = "ok"
    warn = "warn"
    fail = "fail"
    skip = "skip"


@dataclass
class Check:
    id: str
    title: str
    status: Status
    detail: str = ""
    hint: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def failed(self) -> bool:
        return self.status is Status.fail


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)
    denied: list[telemetry.DeniedDomain] = field(default_factory=list)

    def add(self, check: Check) -> Check:
        self.checks.append(check)
        return check

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if c.status is Status.fail]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if c.status is Status.warn]

    @property
    def ok(self) -> bool:
        return not self.failures

    def exit_code(self) -> int:
        if self.failures:
            return 2
        return 0


# -- individual checks ----------------------------------------------------


def check_host_tools(secrets_config: SecretsConfig | None = None) -> list[Check]:
    checks: list[Check] = []
    # `op` is only relevant when a mapping actually uses a 1Password reference;
    # abox reads secrets from files, env vars, the terminal, or the Docker store
    # just as happily.
    op_needed = bool(secrets_config and secrets_config.needs_op())
    for tool in ("docker", "op"):
        path = shell.which(tool)
        if tool == "op" and not op_needed:
            checks.append(
                Check(
                    id="host.op",
                    title="host tool: op (1Password)",
                    status=Status.ok if path else Status.skip,
                    detail=path or "not installed — no mapping uses a 1Password reference",
                )
            )
            continue
        if path:
            status = Status.ok
        elif tool == "docker":
            status = Status.fail
        else:
            status = Status.warn
        checks.append(
            Check(
                id=f"host.{tool}",
                title=f"host tool: {tool}",
                status=status,
                detail=path or "not on PATH",
                hint="" if path else shell.INSTALL_HINTS.get(tool, ""),
            )
        )
    ok, detail = dockerx.daemon_ok()
    checks.append(
        Check(
            id="host.docker-daemon",
            title="docker daemon",
            status=Status.ok if ok else Status.fail,
            detail=f"server {detail}" if ok else detail,
            hint="" if ok else "start Docker Desktop",
        )
    )
    return checks


def check_manifest(manifest: Manifest, config: GlobalConfig) -> Check:
    try:
        config.profile(manifest.profile)
    except AboxError as exc:
        return Check(
            id="manifest.schema",
            title="manifest is valid",
            status=Status.fail,
            detail=exc.message,
            hint=exc.hint or "",
        )
    return Check(
        id="manifest.schema",
        title="manifest is valid",
        status=Status.ok,
        detail=f"project={manifest.project} profile={manifest.profile} "
        f"servers={len(manifest.servers)} egress={len(manifest.egress)}",
    )


def check_servers(
    manifest: Manifest, catalog: Catalog, custom: CustomServers, config: GlobalConfig
) -> list[Check]:
    checks: list[Check] = []
    unknown: list[str] = []
    unpinned: list[str] = []
    remote_catalog: list[str] = []
    poci: list[str] = []
    local: list[str] = []
    for name in manifest.servers:
        server = catalog.get(name)
        if server is None:
            unknown.append(name)
            continue
        if server.is_remote:
            remote_catalog.append(name)
            continue
        if server.is_poci:
            poci.append(name)
            continue
        if server.local_image:
            # `pin: false` — a deliberately unpinned local image. Reported by
            # check_custom_servers as its own warning; not a *failure* here, or
            # this check would order the operator to pin what they opted out of.
            local.append(name)
            continue
        if not server.pinned:
            unpinned.append(f"{name} ({server.image or 'no image'})")

    checks.append(
        Check(
            id="servers.declared",
            title="declared servers resolve",
            status=Status.fail if unknown else Status.ok,
            detail=f"unknown: {', '.join(unknown)}" if unknown else f"{len(manifest.servers)} ok",
            hint="add them to ~/.config/abox/custom-servers.yaml or fix the name"
            if unknown
            else "",
        )
    )
    checks.extend(check_remote_servers(manifest, catalog, remote_catalog))
    checks.extend(check_custom_servers(manifest, custom))
    checks.extend(check_boundary_spanning_servers(manifest))
    checks.append(
        Check(
            id="servers.pinned",
            title="server images are digest-pinned",
            status=Status.fail if unpinned else Status.ok,
            detail=", ".join(unpinned)
            if unpinned
            else f"{len(manifest.servers) - len(remote_catalog) - len(poci) - len(local)} pinned",
            hint="pin with registry/name@sha256:… — a tag can be moved under you"
            if unpinned
            else "",
        )
    )

    if poci:
        checks.append(
            Check(
                id="servers.poci",
                title="dynamically-built servers",
                status=Status.warn,
                detail=f"{', '.join(poci)} — Docker resolves and builds these at run "
                "time; the catalog carries no image reference, so there is nothing "
                "to pin",
                hint="nothing to fix; know that their contents are not fixed by "
                "this manifest the way a digest would fix them",
                data={"poci": poci},
            )
        )

    # The gateway is the one container that mounts the Docker socket. A mutable
    # tag there is a standing offer to swap the most privileged process in the
    # system, so this is a failure on the same footing as `servers.pinned`.
    pinned_gw = config.gateway_image_pinned
    digest = dockerx.image_digest(config.gateway_image) if not pinned_gw else config.gateway_image
    checks.append(
        Check(
            id="gateway.image-pinned",
            title="gateway image is digest-pinned",
            status=Status.ok if pinned_gw else Status.fail,
            detail=config.gateway_image
            if pinned_gw
            else f"{config.gateway_image} (resolves to {digest or 'not pulled yet'})",
            hint="`abox gateway update` resolves the tag and writes the digest"
            if not pinned_gw
            else "",
            data={"resolved": digest or ""},
        )
    )

    checks.append(check_gateway_image_drift(manifest.profile, config))

    # --verify-signatures is a gateway argument; confirm the running container
    # actually carries it rather than trusting that abox started it.
    container = paths.gateway_container(manifest.profile)
    state = dockerx.inspect("container", container)
    if state:
        args = " ".join(state.get("Args") or [])
        checks.append(
            Check(
                id="gateway.verify-signatures",
                title="gateway verifies image signatures",
                status=Status.ok if "--verify-signatures" in args else Status.fail,
                detail=args or "(no args recorded)",
                hint="recreate with `abox gateway up --force`"
                if "--verify-signatures" not in args
                else "",
            )
        )
    return checks


#: Servers whose whole purpose is reaching something the agent's own sandbox
#: restricts. Their tools run in the *gateway's* server containers, not in the
#: agent container — so the agent's egress firewall and mask overlays do not
#: apply to them. That is inherent to the gateway design, not a defect, but it
#: is the kind of thing an operator should decide knowingly.
BOUNDARY_SPANNING_SERVERS: dict[str, str] = {
    "curl": "makes arbitrary HTTP requests from the gateway, which is not behind "
    "the agent's egress allowlist",
    "fetch": "makes arbitrary HTTP requests from the gateway, which is not behind "
    "the agent's egress allowlist",
    "docker": "talks to the Docker daemon — the socket the agent container is "
    "specifically denied",
    "filesystem": "reads and writes paths mounted into its own container, which "
    "are not the agent's masked workspace",
    "shell": "executes commands outside the agent container",
    "desktop-commander": "executes commands outside the agent container",
}


def check_boundary_spanning_servers(manifest: Manifest) -> list[Check]:
    """Name the servers that can reach past the agent's own restrictions."""
    hits = {
        name: BOUNDARY_SPANNING_SERVERS[name]
        for name in manifest.all_servers
        if name in BOUNDARY_SPANNING_SERVERS
    }
    if not hits:
        return []
    detail = "; ".join(f"{name}: {why}" for name, why in sorted(hits.items()))
    return [
        Check(
            id="servers.boundary-spanning",
            title="declared servers that reach past the agent's sandbox",
            status=Status.warn,
            detail=detail,
            hint="MCP tools run in the gateway's containers, so the agent's "
            "firewall and masks do not constrain them — narrow with "
            "`tools:` in agentbox.yaml, or drop the server",
            data={"servers": sorted(hits)},
        )
    ]


def check_custom_servers(manifest: Manifest, custom: CustomServers) -> list[Check]:
    """Servers the operator supplied rather than the Docker catalog.

    The gateway signature-verifies images in the ``docker.io/mcp/*`` namespace
    only (``isDockerMCPImage`` in the gateway), so a custom image from any other
    registry — or a local build — runs unverified regardless of
    ``--verify-signatures``. The digest abox pins is therefore the only
    integrity anchor these images have, which is exactly what ``pin: false``
    gives up.
    """
    declared = [name for name in manifest.servers if name in custom.servers]
    if not declared:
        return []
    pinned = [name for name in declared if custom.servers[name].pin]
    unpinned = [name for name in declared if not custom.servers[name].pin]
    checks: list[Check] = []
    if pinned:
        detail = ", ".join(
            f"{name} ({custom.servers[name].image.split('@')[0]})" for name in pinned
        )
        checks.append(
            Check(
                id="servers.custom",
                title="operator-supplied server images",
                status=Status.warn,
                detail=detail,
                hint="digest-pinned, which is their only integrity anchor: the "
                "gateway signature-verifies docker.io/mcp/* images only, so a "
                "custom image is never signature-checked",
                data={"custom": pinned},
            )
        )
    if unpinned:
        detail = ", ".join(f"{name} ({custom.servers[name].image})" for name in unpinned)
        checks.append(
            Check(
                id="servers.custom-unpinned",
                title="unpinned local server images (pin: false)",
                status=Status.warn,
                detail=detail,
                hint="no digest and no signature check — abox trusts these on "
                "your say-so and will not pull them, so the image must be present "
                "on the daemon before `abox up`",
                data={"custom_unpinned": unpinned},
            )
        )
    return checks


def check_remote_servers(
    manifest: Manifest, catalog: Catalog, catalog_remotes: list[str]
) -> list[Check]:
    """Remote MCP servers change the trust story, so state it plainly.

    They are proxied by the gateway, which means the agent still has exactly one
    endpoint and never learns the remote host — but the third party operating
    that endpoint can change what its tools do at any time, and no digest pin
    can tell you it happened.
    """
    checks: list[Check] = []
    declared = dict(manifest.remote_servers)
    total = len(declared) + len(catalog_remotes)
    if not total:
        return checks

    insecure = sorted(name for name, s in declared.items() if not s.url.startswith("https://"))
    checks.append(
        Check(
            id="remote.transport",
            title="remote MCP endpoints are https",
            status=Status.fail if insecure else Status.ok,
            detail=", ".join(insecure) if insecure else f"{total} remote server(s), all https",
            hint="an http endpoint exposes the gateway's credential in transit"
            if insecure
            else "",
        )
    )

    # The gateway merges catalogs by key and logs only a warning when a name
    # collides, so a locally declared name can silently repoint a catalog server.
    shadowed = sorted(
        name
        for name in declared
        if (entry := catalog.get(name)) is not None and entry.source != "manifest-remote"
    )
    if shadowed:
        checks.append(
            Check(
                id="remote.shadowing",
                title="remote server names do not shadow the catalog",
                status=Status.warn,
                detail=f"{', '.join(shadowed)} also exist(s) in the Docker catalog — "
                "the local definition wins",
                hint="rename the remote entry if you meant to use the catalog server",
                data={"shadowed": shadowed},
            )
        )

    names = sorted([*declared, *catalog_remotes])
    checks.append(
        Check(
            id="remote.trust",
            title="remote MCP servers are third-party operated",
            status=Status.warn,
            detail=f"{', '.join(names)} — proxied by the gateway; the operator of each "
            "endpoint controls what its tools do, and there is no digest to pin",
            hint="the agent still sees exactly one MCP endpoint and cannot reach these "
            "hosts itself; review them the way you would a dependency",
            data={"remote": names},
        )
    )

    oauth_needed = sorted(
        {
            provider
            for name in catalog_remotes
            for provider in (catalog.get(name).oauth_providers if catalog.get(name) else ())
        }
    )
    if oauth_needed:
        checks.append(
            Check(
                id="remote.oauth",
                title="remote servers needing OAuth",
                status=Status.warn,
                detail=", ".join(oauth_needed),
                hint="authorize host-side with `abox mcp oauth <provider>` — the token "
                "lands in the OS keychain and never reaches the agent",
            )
        )
    return checks


def check_secrets(
    manifest: Manifest,
    catalog: Catalog,
    secrets_config: SecretsConfig,
    *,
    deep: bool = True,
) -> list[Check]:
    required = secrets.required_secrets(catalog, manifest.servers)
    for server in manifest.remote_servers.values():
        for entry in server.secrets:
            if entry.name not in required:
                required.append(entry.name)
    if not required and not secrets_config.mappings:
        return [
            Check(
                id="secrets.mapped",
                title="secrets",
                status=Status.ok,
                detail="no declared server needs a secret",
            )
        ]
    try:
        present = secrets.docker_secret_names()
    except AboxError as exc:
        return [
            Check(
                id="secrets.store",
                title="docker secret store",
                status=Status.fail,
                detail=exc.message,
                hint=exc.hint or "",
            )
        ]

    missing = [name for name in required if name not in present]
    checks = [
        Check(
            id="secrets.present",
            title="required secrets exist in the docker store",
            status=Status.fail if missing else Status.ok,
            detail=f"missing: {', '.join(missing)}" if missing else f"{len(required)} present",
            hint="`abox secrets sync` after adding the mapping to secrets.yaml"
            if missing
            else "",
            data={"required": required},
        )
    ]

    if not deep:
        checks.append(
            Check(
                id="secrets.fresh",
                title="secrets match their sources",
                status=Status.skip,
                detail="not checked in preflight",
            )
        )
        return checks

    reports = secrets.check(secrets_config, required=required)
    stale = [r for r in reports if not r.ok]
    external = [r for r in reports if r.status is secrets.SecretStatus.external]
    detail = (
        "; ".join(f"{r.name}: {r.status.value}" for r in stale)
        if stale
        else f"{len(reports)} current"
    )
    if external and not stale:
        detail += f" ({len(external)} managed outside abox)"
    checks.append(
        Check(
            id="secrets.fresh",
            title="secrets match their sources",
            status=Status.warn if stale else Status.ok,
            detail=detail,
            hint="`abox secrets sync` then restart the affected gateway" if stale else "",
        )
    )
    return checks


def check_gateway_image_drift(profile: str, config: GlobalConfig) -> Check:
    """Is the gateway that is *running* the one the config pins?

    Pinning the reference in config.yaml settles what abox will start next time.
    It says nothing about the container already holding the Docker socket, which
    may have been started from an older config, from a tag that has since moved,
    or by hand. So compare the running container's image id — resolved to its
    repo digest, because ``Config.Image`` only echoes whatever was typed.
    """
    container = paths.gateway_container(profile)
    running = dockerx.container_image_digest(container)
    if running is None:
        return Check(
            id="gateway.image-digest",
            title="running gateway matches the pinned digest",
            status=Status.skip,
            detail=f"{container} is not running",
        )
    configured = (
        config.gateway_image
        if config.gateway_image_pinned
        else dockerx.image_digest(config.gateway_image)
    )
    if not configured:
        return Check(
            id="gateway.image-digest",
            title="running gateway matches the pinned digest",
            status=Status.skip,
            detail=f"{config.gateway_image} is not pulled, so there is nothing to compare",
        )
    match = running == configured
    return Check(
        id="gateway.image-digest",
        title="running gateway matches the pinned digest",
        status=Status.ok if match else Status.fail,
        detail=running if match else f"running {running}, configured {configured}",
        hint="`abox gateway up --force` recreates it from the pinned image"
        if not match
        else "",
        data={"running": running, "configured": configured},
    )


def check_gateway(manifest: Manifest, config: GlobalConfig, *, deep: bool = True) -> list[Check]:
    status = gateway.status(manifest.profile, config, deep=deep)
    checks = [
        Check(
            id="gateway.running",
            title=f"gateway {status.container} is running",
            status=Status.ok if status.running else Status.fail,
            detail=status.detail,
            hint="`abox gateway up`" if not status.running else "",
        )
    ]
    if status.running:
        checks.append(
            Check(
                id="gateway.mcp",
                title="gateway answers MCP on abox-net",
                status=Status.ok if status.healthy else (Status.skip if not deep else Status.fail),
                detail=status.detail if deep else "not probed",
                hint=f"`docker logs {status.container}`" if deep and not status.healthy else "",
                data={"url": status.url},
            )
        )
        checks.append(
            Check(
                id="gateway.no-published-ports",
                title="gateway publishes nothing to the host",
                status=Status.ok if not status.published_ports else Status.fail,
                detail=", ".join(status.published_ports) or "no host port bindings",
                hint="recreate with `abox gateway up --force`"
                if status.published_ports
                else "",
            )
        )
        if not status.fingerprint_matches:
            checks.append(
                Check(
                    id="gateway.drift",
                    title="gateway matches the profile's declared servers",
                    status=Status.warn,
                    detail="the running gateway was started with a different server set",
                    hint="`abox gateway up --force`",
                )
            )
    return checks


def check_artifacts(manifest: Manifest, config: GlobalConfig, workspace: Path) -> list[Check]:
    drift = render.detect_drift(manifest, config, workspace)
    if not drift.rendered:
        return [
            Check(
                id="artifacts.rendered",
                title="generated artifacts exist",
                status=Status.fail,
                detail="nothing rendered yet",
                hint="`abox up`",
            )
        ]
    checks = [
        Check(
            id="artifacts.current",
            title="artifacts match the manifest",
            status=Status.warn if drift.manifest_changed else Status.ok,
            detail="manifest changed since last render"
            if drift.manifest_changed
            else "in sync",
            hint="`abox up` to re-render" if drift.manifest_changed else "",
        ),
        Check(
            id="artifacts.integrity",
            title="mounted artifacts are unmodified",
            status=Status.fail if drift.tampered else Status.ok,
            detail=", ".join(drift.tampered) if drift.tampered else "hashes match",
            hint="someone edited the files abox mounts into the container; "
            "re-render with `abox up` and investigate"
            if drift.tampered
            else "",
        ),
        Check(
            id="artifacts.review-copy",
            title=".devcontainer review copy matches",
            status=Status.warn if drift.review_diverged else Status.ok,
            detail=", ".join(drift.review_diverged)
            if drift.review_diverged
            else "review copy in sync",
            hint="the workspace copy is decorative — abox mounts the state-dir copy — "
            "but a divergence means something (or someone) edited it"
            if drift.review_diverged
            else "",
        ),
    ]
    if drift.stale_masks:
        checks.append(
            Check(
                id="artifacts.masks",
                title="mask coverage is current",
                status=Status.warn,
                detail=f"new files match a mask but are unprotected: "
                f"{', '.join(drift.stale_masks[:8])}",
                hint="`abox up` to re-render the mask overlays",
                data={"paths": drift.stale_masks},
            )
        )
    return checks


def check_boundary(manifest: Manifest, config: GlobalConfig, workspace: Path) -> list[Check]:
    from .runner import boundary_checks

    results = boundary_checks(manifest, config, workspace)
    demanding = manifest.run.requires_boundary_gate
    checks: list[Check] = []
    for item in results:
        status = Status.ok if item.ok else (Status.fail if demanding else Status.warn)
        checks.append(
            Check(
                id=f"boundary.{item.name}",
                title=f"boundary: {item.name}",
                status=status,
                detail=item.detail,
                hint="`abox up` to re-render"
                if not item.ok
                else "",
            )
        )
    if demanding:
        failed = [c for c in checks if c.status is Status.fail]
        checks.append(
            Check(
                id="boundary.gate",
                title=f"permission_mode={manifest.run.permission_mode.value} is permitted",
                status=Status.fail if failed else Status.ok,
                detail="all boundary checks pass"
                if not failed
                else f"{len(failed)} boundary check(s) failed",
                hint="abox will refuse to run until these pass, or lower "
                "run.permission_mode in agentbox.yaml"
                if failed
                else "",
            )
        )
    return checks


# -- git tamper diff ------------------------------------------------------

#: Config keys that turn `git` into an execution primitive.
GIT_SENSITIVE_PREFIXES = ("core.hookspath", "alias.", "include.path", "includeif.", "credential.")


def git_config_snapshot(workspace: Path) -> dict[str, str]:
    """Read the interesting subset of ``.git/config`` without invoking git.

    Invoking git here would run the very hooks and aliases this check exists to
    detect, so the file is parsed directly.
    """
    path = workspace / ".git" / "config"
    if not path.is_file():
        return {}
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    try:
        parser.read_string(path.read_text(encoding="utf-8", errors="replace"))
    except configparser.Error:
        return {"__unparseable__": "1"}
    out: dict[str, str] = {}
    for section in parser.sections():
        clean = section.strip().replace('"', "").replace(" ", ".")
        for key, value in parser.items(section):
            full = f"{clean}.{key}".lower()
            if full.startswith(GIT_SENSITIVE_PREFIXES):
                out[full] = value
    hooks = workspace / ".git" / "hooks"
    if hooks.is_dir():
        live = sorted(
            p.name for p in hooks.iterdir() if p.is_file() and not p.name.endswith(".sample")
        )
        if live:
            out["__hooks__"] = ",".join(live)
    return out


def _git_state_path(workspace: Path) -> Path:
    return paths.project_state_dir(workspace) / "git-snapshot.json"


def _read_snapshot(workspace: Path) -> dict[str, Any]:
    path = _git_state_path(workspace)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_snapshot(workspace: Path, **sections: Any) -> None:
    """Merge sections into git-snapshot.json without dropping the others."""
    paths.ensure_project_state(workspace)
    data = _read_snapshot(workspace)
    data.update(sections)
    data["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    path = _git_state_path(workspace)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


# -- execution-adjacent surface -------------------------------------------

#: Per-glob file cap. `.idea/` and friends can be enormous, and a fingerprint
#: nobody can compute is worse than one that says where it stopped — so the
#: overflow is reported rather than silently dropped.
WATCH_FILE_CAP = 500


def watch_snapshot(workspace: Path, globs: Iterable[str]) -> tuple[dict[str, str], list[str]]:
    """sha256 every file matched by the watch globs. Returns (digests, capped globs).

    Directories are walked, so `.github/workflows` covers a workflow added after
    the baseline. Symlinks are recorded by their target text rather than
    followed: a symlink swapped to point at something else is exactly the kind
    of edit this exists to notice, and following it would hide the swap.
    """
    digests: dict[str, str] = {}
    capped: list[str] = []

    def record(path: Path) -> None:
        try:
            rel = path.relative_to(workspace).as_posix()
        except ValueError:
            return
        try:
            if path.is_symlink():
                digests[rel] = "symlink:" + hashlib.sha256(
                    os.readlink(path).encode("utf-8", "replace")
                ).hexdigest()
            elif path.is_file():
                digests[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            digests[rel] = "unreadable"

    for glob in globs:
        seen = 0
        for match in sorted(workspace.glob(glob)):
            if match.is_dir() and not match.is_symlink():
                for child in sorted(p for p in match.rglob("*") if not p.is_dir()):
                    if seen >= WATCH_FILE_CAP:
                        capped.append(glob)
                        break
                    record(child)
                    seen += 1
                else:
                    continue
                break
            if seen >= WATCH_FILE_CAP:
                capped.append(glob)
                break
            record(match)
            seen += 1
    return digests, sorted(set(capped))


def check_exec_surface(
    manifest: Manifest, config: GlobalConfig, workspace: Path, *, update: bool = False
) -> Check:
    """Did anything that executes *outside* this sandbox change while it ran?

    /workspace is a live bind of real files, so the agent can write a CI
    workflow, a Makefile target, or a package.json script. None of those run in
    the container — they run on a CI runner, on the next `make`, on the next
    `npm install`, on the machine of whoever opens the project next. That is a
    compromise on a delay, and it is invisible to every control abox has,
    because every control abox has is about this container's own execution.

    Masking the whole class would close it and break ordinary work, so the
    default is to watch. This is a warning rather than a failure on purpose: an
    agent editing package.json is normal, and a check that fails on normal work
    is a check people learn to skip. What it must not do is stay quiet.
    """
    globs = merged_watch(manifest, config)
    if not globs:
        return Check(
            id="workspace.exec-surface",
            title="execution-adjacent files unchanged",
            status=Status.skip,
            detail="nothing watched (mounts.watch and defaults.watch are both empty)",
        )

    current, capped = watch_snapshot(workspace, globs)
    previous = dict(_read_snapshot(workspace).get("watch") or {})
    first_run = "watch" not in _read_snapshot(workspace)

    if update or first_run:
        _write_snapshot(workspace, watch=current)

    cap_note = (
        f" — {', '.join(capped)} exceeded {WATCH_FILE_CAP} files and is only "
        "fingerprinted up to that point"
        if capped
        else ""
    )

    if first_run:
        return Check(
            id="workspace.exec-surface",
            title="execution-adjacent files unchanged",
            status=Status.ok,
            detail=f"baseline recorded ({len(current)} file(s)){cap_note}",
            data={"watched": sorted(current), "capped": capped},
        )

    added = sorted(k for k in current if k not in previous)
    changed = sorted(k for k in current if k in previous and previous[k] != current[k])
    removed = sorted(set(previous) - set(current))
    if added or changed or removed:
        parts = []
        if added:
            parts.append("added: " + ", ".join(added))
        if changed:
            parts.append("changed: " + ", ".join(changed))
        if removed:
            parts.append("removed: " + ", ".join(removed))
        return Check(
            id="workspace.exec-surface",
            title="execution-adjacent files unchanged",
            status=Status.warn,
            detail="; ".join(parts) + cap_note,
            hint="these execute outside the sandbox — on a CI runner, on the next "
            "build, or when an editor opens the project. Read the diff before you "
            "push or run anything, then `abox doctor --accept-watch` to re-baseline. "
            "Add the path to `mounts.mask` to stop the agent writing it at all",
            data={"added": added, "changed": changed, "removed": removed, "capped": capped},
        )
    return Check(
        id="workspace.exec-surface",
        title="execution-adjacent files unchanged",
        status=Status.ok,
        detail=f"{len(current)} file(s), unchanged since last check{cap_note}",
        data={"watched": sorted(current), "capped": capped},
    )


def check_egress_proxy(manifest: Manifest, config: GlobalConfig, workspace: Path) -> list[Check]:
    """The SNI proxy, when the operator has turned it on.

    It is the difference between an address-level and a domain-level allowlist,
    so whether it is actually running is a boundary fact, not a detail.
    """
    from . import proxy as proxy_mod

    if not config.egress_proxy.enabled:
        return []
    status = proxy_mod.status(manifest, config, workspace)
    checks = [
        Check(
            id="egress.proxy",
            title="SNI egress proxy is running",
            status=Status.ok if status.ok else Status.fail,
            detail=status.detail
            if status.ok
            else f"{status.container}: {status.detail}",
            hint="`abox up` — with the proxy configured but absent the agent has "
            "no egress path at all, and the firewall refuses to come up"
            if not status.ok
            else "",
        )
    ]
    if status.published_ports:
        checks.append(
            Check(
                id="egress.proxy-ports",
                title="the egress proxy publishes nothing",
                status=Status.fail,
                detail=", ".join(status.published_ports),
            )
        )
    denied = proxy_mod.denied_names(manifest.project)
    if denied:
        names = sorted({d["sni"] for d in denied})
        checks.append(
            Check(
                id="egress.proxy-denied",
                title="connections refused by SNI",
                status=Status.warn,
                detail=", ".join(names[:8]),
                hint="these were connected to, not merely resolved — a stronger "
                "signal than the DNS queue. `abox egress add <domain>` to allow",
                data={"denied": names},
            )
        )
    return checks


def check_shared_addresses(manifest: Manifest, config: GlobalConfig) -> Check:
    """Allowlisted domains that resolve to the same address.

    The firewall matches on IP, so it cannot tell two domains apart when they
    share one — a request to an allowed IP carrying a different SNI or Host
    header reaches whatever else lives there. CDN-fronted domains (pypi.org and
    files.pythonhosted.org are both Fastly) make this concrete rather than
    theoretical, and no ipset rule can close it: only an SNI-aware proxy can.
    """
    import socket

    allow = merged_egress(manifest, config)
    by_addr: dict[str, list[str]] = {}
    for host in allow:
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        except OSError:
            continue
        for addr in {info[4][0] for info in infos}:
            by_addr.setdefault(addr, []).append(host)
    shared = {a: hs for a, hs in by_addr.items() if len(hs) > 1}
    if shared and config.egress_proxy.enabled:
        return Check(
            id="egress.shared-addresses",
            title="allowlisted domains share addresses",
            status=Status.ok,
            detail=f"{len(shared)} shared address(es), but the SNI proxy decides "
            "by name, so sharing an address grants nothing",
        )
    if not shared:
        return Check(
            id="egress.shared-addresses",
            title="allowlisted domains do not share addresses",
            status=Status.ok,
            detail=f"{len(allow)} domain(s), no overlap seen right now",
        )
    groups = "; ".join(f"{a}: {', '.join(sorted(hs))}" for a, hs in sorted(shared.items()))
    return Check(
        id="egress.shared-addresses",
        title="allowlisted domains share addresses",
        status=Status.warn,
        detail=groups,
        hint="the firewall matches IPs, so anything else reachable at these "
        "addresses is reachable too (SNI/Host swapping). Shared-CDN domains "
        "cannot be separated by ipset — treat the allowlist as address-level, "
        "not domain-level",
        data={"shared": {a: sorted(hs) for a, hs in shared.items()}},
    )


def check_git_tamper(workspace: Path, *, update: bool = False) -> Check:
    current = git_config_snapshot(workspace)
    stored = _read_snapshot(workspace)
    previous = dict(stored.get("keys") or {})

    if not (workspace / ".git").exists():
        return Check(
            id="git.tamper",
            title="git config unchanged",
            status=Status.skip,
            detail="not a git repository",
        )

    added = {k: v for k, v in current.items() if k not in previous}
    changed = {k: v for k, v in current.items() if k in previous and previous[k] != v}
    removed = sorted(set(previous) - set(current))
    first_run = "keys" not in stored

    if update or first_run:
        _write_snapshot(workspace, keys=current)

    if first_run:
        return Check(
            id="git.tamper",
            title="git config unchanged",
            status=Status.ok,
            detail=f"baseline recorded ({len(current)} sensitive key(s))",
        )
    if added or changed or removed:
        parts = []
        if added:
            parts.append("added: " + ", ".join(sorted(added)))
        if changed:
            parts.append("changed: " + ", ".join(sorted(changed)))
        if removed:
            parts.append("removed: " + ", ".join(removed))
        return Check(
            id="git.tamper",
            title="git config unchanged",
            status=Status.fail,
            detail="; ".join(parts),
            hint="hooks and aliases execute on ordinary git commands — review these "
            "before the next run, then `abox doctor --accept-git` to re-baseline",
            data={"added": added, "changed": changed, "removed": removed},
        )
    return Check(
        id="git.tamper",
        title="git config unchanged",
        status=Status.ok,
        detail=f"{len(current)} sensitive key(s), unchanged since last check",
    )


# -- egress review queue --------------------------------------------------


def check_egress_queue(
    manifest: Manifest, config: GlobalConfig, workspace: Path
) -> tuple[Check, list[telemetry.DeniedDomain]]:
    allow = effective_allowlist(manifest, config)
    denied = telemetry.review_queue(workspace, allow, ignored=manifest.egress_ignored)
    acknowledged = (
        f" ({len(manifest.egress_ignored)} previously ignored)"
        if manifest.egress_ignored
        else ""
    )
    if not denied:
        return (
            Check(
                id="egress.queue",
                title="egress review queue",
                status=Status.ok,
                detail=f"nothing undecided{acknowledged}",
            ),
            [],
        )
    top = ", ".join(f"{d.name} (x{d.count})" for d in denied[:5])
    return (
        Check(
            id="egress.queue",
            title="egress review queue",
            status=Status.warn,
            detail=f"{len(denied)} domain(s) looked up but not allowed{acknowledged}: {top}",
            hint="`abox egress add <domain>` to allow it, or "
            "`abox egress ignore <domain>` to record that you have decided against it",
            data={"denied": [d.to_dict() for d in denied]},
        ),
        denied,
    )


# -- agent hygiene --------------------------------------------------------


def check_agent_hygiene(workspace: Path, manifest: Manifest | None = None) -> list[Check]:
    rendered = render.inspect_rendered(workspace)
    if not rendered:
        return []
    run_args = [str(a) for a in (rendered.get("run_args") or [])]
    sock = [a for a in run_args if "docker.sock" in a or "/var/run/docker" in a]
    ports = [a for a in run_args if a in ("-p", "--publish") or a.startswith("--publish=")]
    privileged = [a for a in run_args if "privileged" in a]

    return [
        Check(
            id="agent.no-docker-sock",
            title="agent has no docker socket",
            status=Status.fail if sock else Status.ok,
            detail=", ".join(sock) if sock else "no socket mount",
            hint="a socket mount hands the agent the whole host daemon" if sock else "",
        ),
        Check(
            id="agent.no-published-ports",
            title="agent publishes no ports",
            status=Status.fail if ports else Status.ok,
            detail=", ".join(ports) if ports else "no published ports",
        ),
        Check(
            id="agent.not-privileged",
            title="agent is not privileged",
            status=Status.fail if privileged else Status.ok,
            detail=", ".join(privileged) if privileged else "no privileged flag",
        ),
        _mcp_endpoint_check(manifest),
    ]


def check_auth_credential(manifest: Manifest, config: GlobalConfig, workspace: Path) -> Check:
    """The credential the agent holds whether or not you attached anything.

    ``~/.claude`` is a per-project volume, and Claude Code's OAuth credential
    lives in it. The agent runs as the user that owns it, so the agent can read
    it — and everything the env-secrets check says about exfiltration to an
    allowed domain applies here unchanged. Reporting attached secrets loudly
    while staying silent about this one would be picking the flattering half.
    """
    allowed = merged_egress(manifest, config)
    detail = (
        f"{paths.claude_volume(workspace)} mounted at "
        f"/home/{config.remote_user}/.claude — readable by the agent"
    )
    hint = (
        f"the agent can read and transmit it to any allowed domain "
        f"({len(allowed)} currently allowed), exactly as with an attached secret"
    )
    if not manifest.run.single_mcp_endpoint:
        hint += (
            ". run.connectors is on, so its blast radius is not just this "
            "sandbox — it is whatever the connectors on that account reach"
        )
    return Check(
        id="agent.auth-credential",
        title="the agent holds a Claude credential",
        status=Status.warn,
        detail=detail,
        hint=hint,
        data={
            "volume": paths.claude_volume(workspace),
            "allowed_domains": len(allowed),
            "connectors": not manifest.run.single_mcp_endpoint,
        },
    )


def check_agent_secrets(manifest: Manifest, config: GlobalConfig) -> list[Check]:
    """The one place abox hands the agent a credential. Report it every time.

    The containment story changes shape here: the agent can read these, so the
    egress allowlist stops being defence-in-depth and becomes the thing standing
    between a credential and an attacker who has influenced the model.
    """
    if not manifest.env_secrets:
        return []
    pairs = ", ".join(f"{env}←{name}" for env, name in sorted(manifest.env_secrets.items()))
    allowed = merged_egress(manifest, config)
    checks = [
        Check(
            id="agent.env-secrets",
            title="the agent holds secrets in its environment",
            status=Status.warn,
            detail=f"{len(manifest.env_secrets)} secret(s): {pairs}",
            hint="the agent can read, print, and transmit these to any allowed "
            f"domain ({len(allowed)} currently allowed) — keep the egress list "
            "tight, and expect them in `docker inspect` on the agent container",
            data={"env": sorted(manifest.env_secrets)},
        )
    ]
    try:
        present = secrets.docker_secret_names()
    except AboxError as exc:
        checks.append(
            Check(
                id="agent.env-secrets-present",
                title="agent secrets exist in the store",
                status=Status.warn,
                detail=exc.message,
            )
        )
        return checks
    missing = sorted(n for n in manifest.env_secrets.values() if n not in present)
    checks.append(
        Check(
            id="agent.env-secrets-present",
            title="agent secrets exist in the store",
            status=Status.fail if missing else Status.ok,
            detail=f"missing: {', '.join(missing)}" if missing else "all present",
            hint="`abox secrets set <name>` — the container will not start "
            "with an unresolvable se:// reference"
            if missing
            else "",
        )
    )
    return checks


def _mcp_endpoint_check(manifest: Manifest | None) -> Check:
    """State the endpoint count as it actually is, not as the design prefers."""
    if manifest is not None and not manifest.run.single_mcp_endpoint:
        return Check(
            id="agent.single-mcp-endpoint",
            title="agent MCP endpoints",
            status=Status.warn,
            detail="the gateway plus the connectors on your claude.ai account "
            "(run.connectors is on)",
            hint="connector tool calls do not pass through the gateway, so they "
            "are absent from `abox logs --gateway` and their capabilities are not "
            "declared in agentbox.yaml — prefer `abox mcp add <name>` for anything "
            "the Docker catalog carries",
        )
    return Check(
        id="agent.single-mcp-endpoint",
        title="agent has exactly one MCP endpoint",
        status=Status.ok,
        detail="claude is invoked with --mcp-config /opt/abox/mcp.json "
        "--strict-mcp-config",
    )


# -- entry points ---------------------------------------------------------


def preflight(
    manifest: Manifest,
    config: GlobalConfig,
    workspace: Path,
    *,
    catalog: Catalog | None = None,
) -> Report:
    """The fast subset ``abox run`` gates on."""
    report = Report()
    report.add(check_manifest(manifest, config))
    for check in check_gateway(manifest, config, deep=True):
        report.add(check)
    for check in check_artifacts(manifest, config, workspace):
        report.add(check)
    for check in check_boundary(manifest, config, workspace):
        report.add(check)
    for check in check_agent_hygiene(workspace, manifest):
        report.add(check)
    for check in check_agent_secrets(manifest, config):
        report.add(check)
    if catalog is not None:
        for check in check_secrets(manifest, catalog, SecretsConfig.load(), deep=False):
            report.add(check)
    return report


def full(
    manifest: Manifest,
    config: GlobalConfig,
    workspace: Path,
    catalog: Catalog,
    custom: CustomServers,
    secrets_config: SecretsConfig,
    *,
    accept_git: bool = False,
    accept_watch: bool = False,
    deep_secrets: bool = True,
) -> Report:
    report = Report()
    for check in check_host_tools(secrets_config):
        report.add(check)
    report.add(check_manifest(manifest, config))
    for check in check_servers(manifest, catalog, custom, config):
        report.add(check)
    for check in check_secrets(manifest, catalog, secrets_config, deep=deep_secrets):
        report.add(check)
    for check in check_gateway(manifest, config, deep=True):
        report.add(check)
    for check in check_artifacts(manifest, config, workspace):
        report.add(check)
    for check in check_boundary(manifest, config, workspace):
        report.add(check)
    for check in check_agent_secrets(manifest, config):
        report.add(check)
    report.add(check_auth_credential(manifest, config, workspace))
    for check in check_egress_proxy(manifest, config, workspace):
        report.add(check)
    report.add(check_shared_addresses(manifest, config))
    report.add(check_git_tamper(workspace, update=accept_git))
    report.add(check_exec_surface(manifest, config, workspace, update=accept_watch))
    queue_check, denied = check_egress_queue(manifest, config, workspace)
    report.add(queue_check)
    report.denied = denied
    for check in check_agent_hygiene(workspace, manifest):
        report.add(check)
    return report


def summarize(report: Report) -> str:
    counts = dict.fromkeys(Status, 0)
    for check in report.checks:
        counts[check.status] += 1
    return (
        f"{counts[Status.ok]} ok, {counts[Status.warn]} warn, "
        f"{counts[Status.fail]} fail, {counts[Status.skip]} skipped"
    )


def as_json(report: Report) -> str:
    return json.dumps(
        {
            "checks": [
                {
                    "id": c.id,
                    "title": c.title,
                    "status": c.status.value,
                    "detail": c.detail,
                    "hint": c.hint,
                    "data": c.data,
                }
                for c in report.checks
            ],
            "denied": [d.to_dict() for d in report.denied],
            "ok": report.ok,
        },
        indent=2,
    )


def permission_mode_note(manifest: Manifest) -> str:
    if manifest.run.permission_mode is PermissionMode.bypass_permissions:
        return (
            "permission_mode=bypassPermissions: the agent acts without prompting, "
            "so abox refuses the run unless every boundary check passes"
        )
    return f"permission_mode={manifest.run.permission_mode.value}"

