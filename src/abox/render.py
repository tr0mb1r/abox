"""Render the generated artifacts and track their drift.

Two copies of every artifact are produced:

* ``<state>/artifacts/`` — **authoritative**. Owned by the host user, mounted
  read-only into the container at ``/opt/abox``. ``runspec.json`` there is the
  literal Docker argv abox executes. The agent cannot reach any of it.
* ``<workspace>/.devcontainer/`` — a reviewable, version-controllable copy for
  humans and editors. abox never reads it back.

That split matters: ``.devcontainer/`` lives inside the workspace the agent can
write, so an agent that rewrote its own firewall script would otherwise be
choosing the rules for the next run. Here the workspace copy is decorative and
``abox doctor`` reports any divergence as tampering.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from . import __version__, dockerx, paths
from .errors import RenderError
from .gateway import GatewaySpec, mcp_config
from .manifest import (
    CONNECTOR_EGRESS,
    GlobalConfig,
    Manifest,
    merged_egress,
    merged_masks,
)

TEMPLATE_DIR = Path(__file__).parent / "templates"

#: The authoritative provisioning artifact: the exact `docker build` and
#: `docker run` argv abox will use. `devcontainer.json` is rendered alongside it
#: for editors, but abox never reads it back — dropping the devcontainer CLI is
#: what keeps the host free of npm.
ARTIFACT_RUNSPEC = "runspec.json"
ARTIFACT_DEVCONTAINER = "devcontainer.json"
ARTIFACT_DOCKERFILE = "Dockerfile"
ARTIFACT_FIREWALL = "init-firewall.sh"
ARTIFACT_MCP = "mcp.json"
ARTIFACT_SETTINGS = "settings.json"
ARTIFACT_PROXY = "proxy.conf"
MANIFEST_OF_ARTIFACTS = "artifacts.json"

#: Docker's embedded DNS server, reachable on container loopback.
DOCKER_EMBEDDED_DNS = "127.0.0.11"


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
        autoescape=False,  # noqa: S701 - rendering shell/JSON, not HTML
    )


def artifacts_dir(workspace: Path) -> Path:
    d = paths.project_state_dir(workspace) / "artifacts"
    d.mkdir(parents=True, exist_ok=True)
    d.chmod(0o700)
    return d


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def manifest_digest(manifest: Manifest, config: GlobalConfig) -> str:
    """Digest over everything that changes a rendered artifact."""
    payload = json.dumps(
        {
            "manifest": manifest.model_dump(mode="json"),
            "network": config.network,
            "gateway_image": config.gateway_image,
            "agent_base_image": config.agent_base_image,
            "agent_env": config.agent_env,
            "claude_version": config.claude_version,
            "toolchain_versions": config.toolchain_versions,
            "egress_ports": config.egress_ports,
            "scoped_dns": config.scoped_dns,
            "egress_proxy": config.egress_proxy.model_dump(mode="json"),
            "remote_user": config.remote_user,
            "profile": config.profile(manifest.profile).model_dump(mode="json"),
            "defaults": config.defaults.model_dump(mode="json"),
        },
        sort_keys=True,
    )
    return sha256_text(payload)


# -- masks ----------------------------------------------------------------


@dataclass(frozen=True)
class MaskEntry:
    """One path that gets an empty read-only overlay."""

    glob: str
    relpath: str
    is_dir: bool
    existed: bool
    #: False when the path's parent does not exist in the workspace. Docker
    #: cannot create a mountpoint under a directory that is not there, and a
    #: bind mount is fixed at container start — so a mask over
    #: ``.git/hooks`` in a non-repo protects nothing and must not be emitted.
    mountable: bool = True

    @property
    def target(self) -> str:
        return f"/workspace/{self.relpath}"


def expand_masks(workspace: Path, globs: Iterable[str]) -> list[MaskEntry]:
    """Expand mask globs against the current workspace.

    A literal (glob-free) entry is masked whether or not it exists yet — mounting
    an empty file over a path that does not exist still shadows a file created
    later in the run. A glob can only cover what is on disk at render time; the
    gap is reported by :func:`stale_masks`.
    """
    entries: list[MaskEntry] = []
    seen: set[str] = set()
    workspace = workspace.resolve()

    for pattern in globs:
        is_glob = any(ch in pattern for ch in "*?[")
        if not is_glob:
            rel = pattern.rstrip("/")
            target = workspace / rel
            if rel in seen:
                continue
            seen.add(rel)
            entries.append(
                MaskEntry(
                    glob=pattern,
                    relpath=rel,
                    is_dir=target.is_dir() or pattern.endswith("/"),
                    existed=target.exists(),
                    mountable=target.exists() or target.parent.is_dir(),
                )
            )
            continue

        for match in sorted(workspace.glob(pattern)):
            try:
                rel = str(match.relative_to(workspace))
            except ValueError:  # pragma: no cover - glob cannot escape the root
                continue
            if rel in seen:
                continue
            seen.add(rel)
            entries.append(
                MaskEntry(glob=pattern, relpath=rel, is_dir=match.is_dir(), existed=True)
            )
    return entries


def stale_masks(workspace: Path, globs: Iterable[str], rendered: Iterable[str]) -> list[str]:
    """Files that now match a mask glob but were not covered at render time.

    Unmountable entries are excluded: a mask whose parent directory does not
    exist was never emitted and re-rendering would not emit it either, so
    reporting it would be a warning the operator can never clear.
    """
    covered = set(rendered)
    current = {e.relpath for e in expand_masks(workspace, globs) if e.mountable}
    return sorted(current - covered)


def mask_mounts(workspace: Path, entries: Iterable[MaskEntry]) -> list[str]:
    empty_file = paths.empty_mask_file(workspace)
    empty_dir = paths.empty_mask_dir(workspace)
    mounts: list[str] = []
    for entry in entries:
        if not entry.mountable:
            continue
        source = empty_dir if entry.is_dir else empty_file
        mounts.append(f"source={source},target={entry.target},type=bind,readonly")
    return mounts


# -- rendering ------------------------------------------------------------


@dataclass
class RenderResult:
    workspace: Path
    artifacts: dict[str, str] = field(default_factory=dict)
    masked_paths: list[str] = field(default_factory=list)
    context_mounts: list[tuple[str, str]] = field(default_factory=list)
    egress: list[str] = field(default_factory=list)
    digest: str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def config_path(self) -> Path:
        return artifacts_dir(self.workspace) / ARTIFACT_RUNSPEC

    def hashes(self) -> dict[str, str]:
        return {name: sha256_text(body) for name, body in self.artifacts.items()}


def agent_settings(config: GlobalConfig) -> dict[str, Any]:
    """Claude Code settings abox controls, rendered read-only into /opt/abox.

    Passed with ``--settings`` so they live outside the workspace and outside the
    ``~/.claude`` volume — the agent can neither edit them nor drop a competing
    file somewhere Claude Code would prefer.
    """
    settings: dict[str, Any] = {}
    if config.rtk.enabled:
        settings["hooks"] = {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [{"type": "command", "command": "rtk hook claude"}],
                }
            ]
        }
    return settings


def image_tag(manifest: Manifest, digest: str) -> str:
    """Content-addressed image tag: a manifest change means a new tag."""
    return f"abox-agent-{manifest.project}:{digest[:12]}"


def build_runspec(
    manifest: Manifest,
    config: GlobalConfig,
    workspace: Path,
    spec: GatewaySpec,
    *,
    extra_mounts: list[str],
    digest: str,
) -> dict[str, Any]:
    """The exact Docker invocation abox will make.

    This is what ``doctor`` audits. Checking the argv abox actually runs beats
    checking a devcontainer.json that some other tool would have interpreted.
    """
    user = config.remote_user
    volume = paths.claude_volume(workspace)
    mounts: list[str] = [
        f"type=bind,source={workspace},target=/workspace",
        f"type=volume,source={volume},target=/home/{user}/.claude",
        f"type=bind,source={artifacts_dir(workspace)},target=/opt/abox,readonly",
        # /var/log/abox is deliberately NOT bind-mounted. Docker Desktop does not
        # enforce uid or mode on a bind, so an agent could truncate its own audit
        # trail through one — the egress review queue is only worth reading if the
        # agent cannot edit it. Inside the container it is root-owned 0755, which
        # a real filesystem does enforce, and abox harvests it at teardown.
        *extra_mounts,
    ]
    run_args: list[str] = [
        "--network",
        config.network,
        "--cap-add",
        "NET_ADMIN",
        "--cap-add",
        "NET_RAW",
        "--hostname",
        f"agent-{manifest.project}",
        "--user",
        user,
        "--workdir",
        "/workspace",
        "--label",
        f"{dockerx.LABEL_MANAGED}=true",
        "--label",
        f"{dockerx.LABEL_ROLE}=agent",
        "--label",
        f"{dockerx.LABEL_PROJECT}={manifest.project}",
        "--label",
        f"{dockerx.LABEL_PROFILE}={manifest.profile}",
    ]
    for mount in mounts:
        run_args += ["--mount", mount]
    for key, value in {
        "ABOX_PROJECT": manifest.project,
        "ABOX_PROFILE": manifest.profile,
        "ABOX_GATEWAY_URL": spec.url,
        "ABOX_RUN_LOG_DIR": "/var/log/abox",
        "CLAUDE_CONFIG_DIR": f"/home/{user}/.claude",
        **config.agent_env,
        # `se://` is resolved by the Docker daemon at container start, so the
        # value is never read by abox and never lands in this runspec.
        **{
            env: f"se://docker/mcp/{secret}"
            for env, secret in manifest.env_secrets.items()
        },
        # The manifest wins over the global default: asking for connectors and
        # then having them switched off by an env var would be a silent no-op.
        **(
            {"ENABLE_CLAUDEAI_MCP_SERVERS": "true"}
            if manifest.run.connectors
            else {}
        ),
    }.items():
        run_args += ["--env", f"{key}={value}"]

    return {
        "abox_version": __version__,
        "manifest_digest": digest,
        "image": image_tag(manifest, digest),
        "remote_user": user,
        "build": {
            "args": {
                "CLAUDE_VERSION": config.claude_version,
                **{
                    f"{name.upper()}_VERSION": version
                    for name, version in config.toolchain_versions.items()
                },
            },
        },
        "run_args": run_args,
        "logs": "/var/log/abox",
        "firewall": "/opt/abox/init-firewall.sh",
        "mcp_config": "/opt/abox/mcp.json",
        "settings": "/opt/abox/settings.json" if agent_settings(config) else "",
        "toolchains": list(manifest.toolchains),
    }


def render(
    manifest: Manifest,
    config: GlobalConfig,
    workspace: Path,
    spec: GatewaySpec,
    *,
    refresh_interval: int = 300,
) -> RenderResult:
    """Render every artifact into memory. Nothing is written here."""
    workspace = workspace.resolve()
    paths.ensure_project_state(workspace)
    env = _env()

    masks = merged_masks(manifest, config)
    mask_entries = expand_masks(workspace, masks)
    context_pairs = manifest.mounts.context_mounts()
    warnings: list[str] = []

    extra_mounts = mask_mounts(workspace, mask_entries)
    for entry in mask_entries:
        if not entry.mountable:
            warnings.append(
                f"mask {entry.glob!r} skipped: {Path(entry.relpath).parent} does not exist "
                "in the workspace, so there is nothing to shadow yet"
            )
    for host, target in context_pairs:
        if not host.exists():
            warnings.append(f"context dir does not exist: {host}")
            continue
        extra_mounts.append(f"source={host},target={target},type=bind,readonly")

    egress = merged_egress(
        manifest,
        config,
        extra=list(CONNECTOR_EGRESS) if manifest.run.connectors else [],
    )
    digest = manifest_digest(manifest, config)

    runspec = build_runspec(
        manifest, config, workspace, spec, extra_mounts=extra_mounts, digest=digest
    )

    devcontainer = env.get_template("devcontainer.json.j2").render(
        abox_version=__version__,
        project=manifest.project,
        profile=manifest.profile,
        network=config.network,
        workspace=str(workspace),
        claude_volume=paths.claude_volume(workspace),
        artifacts_dir=str(artifacts_dir(workspace)),
        run_log_dir=str(paths.current_run_dir(workspace)),
        extra_mounts=extra_mounts,
        toolchains=manifest.toolchains,
        remote_user=config.remote_user,
        image=runspec["image"],
        gateway_url=spec.url,
        manifest_digest=digest,
        rendered_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        masked_paths=[e.relpath for e in mask_entries if e.mountable],
    )
    _assert_valid_json(devcontainer)

    dockerfile = env.get_template("Dockerfile.j2").render(
        abox_version=__version__,
        project=manifest.project,
        base_image=config.agent_base_image,
        remote_user=config.remote_user,
        toolchains=manifest.toolchains,
        claude_version=config.claude_version,
        versions=config.toolchain_versions,
        rtk=config.rtk,
    )

    settings = json.dumps(agent_settings(config), indent=2) + "\n"

    proxy_conf = env.get_template("proxy.conf.j2").render(
        abox_version=__version__,
        project=manifest.project,
        egress=egress,
        port=config.egress_proxy.port,
        timeout=config.egress_proxy.timeout,
        resolver=DOCKER_EMBEDDED_DNS,
    )

    firewall = env.get_template("init-firewall.sh.j2").render(
        abox_version=__version__,
        project=manifest.project,
        egress=egress,
        gateway_host=spec.container,
        gateway_port=spec.port,
        upstream_dns=DOCKER_EMBEDDED_DNS,
        refresh_interval=refresh_interval,
        selftest_allowed=egress[0] if egress else "api.anthropic.com",
        egress_ports=config.egress_ports,
        scoped_dns=config.scoped_dns,
        proxy_enabled=config.egress_proxy.enabled,
        proxy_host=f"abox-proxy-{manifest.project}",
        proxy_port=config.egress_proxy.port,
    )

    mcp = json.dumps(mcp_config(spec), indent=2) + "\n"

    return RenderResult(
        workspace=workspace,
        artifacts={
            ARTIFACT_RUNSPEC: json.dumps(runspec, indent=2, sort_keys=True) + "\n",
            ARTIFACT_DEVCONTAINER: devcontainer,
            ARTIFACT_DOCKERFILE: dockerfile,
            ARTIFACT_FIREWALL: firewall,
            ARTIFACT_MCP: mcp,
            ARTIFACT_SETTINGS: settings,
            ARTIFACT_PROXY: proxy_conf,
        },
        masked_paths=[e.relpath for e in mask_entries if e.mountable],
        context_mounts=[(str(h), t) for h, t in context_pairs],
        egress=egress,
        digest=digest,
        warnings=warnings,
    )


def _assert_valid_json(text: str) -> None:
    """devcontainer.json is JSONC; strip line comments before validating."""
    stripped = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("//")
    )
    try:
        json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise RenderError(
            f"rendered devcontainer.json is not valid JSON: {exc}",
            hint="this is an abox template bug — please report the manifest that triggered it",
        ) from exc


def write(result: RenderResult, *, workspace_copy: bool = True) -> dict[str, Path]:
    """Write artifacts to the authoritative dir and (optionally) the workspace."""
    written: dict[str, Path] = {}
    target_dir = artifacts_dir(result.workspace)

    for name, body in result.artifacts.items():
        path = target_dir / name
        # The final mode is read-only so nothing on the host casually edits what
        # the container mounts; re-opening it for a re-render therefore needs the
        # write bit back first.
        if path.exists():
            path.chmod(0o600)
        path.write_text(body, encoding="utf-8")
        path.chmod(0o500 if name.endswith(".sh") else 0o400)
        written[name] = path

    state = {
        "digest": result.digest,
        "rendered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "abox_version": __version__,
        "hashes": result.hashes(),
        "masked_paths": result.masked_paths,
        "egress": result.egress,
    }
    index = target_dir / MANIFEST_OF_ARTIFACTS
    index.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    index.chmod(0o600)

    if workspace_copy:
        review_dir = paths.devcontainer_dir(result.workspace)
        review_dir.mkdir(parents=True, exist_ok=True)
        for name, body in result.artifacts.items():
            if name in (ARTIFACT_MCP, ARTIFACT_RUNSPEC, ARTIFACT_SETTINGS):
                # mcp.json carries the gateway bearer token and the runspec is
                # full of host paths; neither belongs in the repo.
                continue
            path = review_dir / name
            if path.exists():
                path.chmod(0o644)
            path.write_text(body, encoding="utf-8")
            if name.endswith(".sh"):
                path.chmod(0o755)
        (review_dir / ".abox-generated").write_text(
            "Files here are generated by abox and are a REVIEW COPY only.\n"
            "The copy abox actually mounts lives outside the workspace so the agent\n"
            "cannot modify the rules that constrain it. Run `abox doctor` to compare.\n",
            encoding="utf-8",
        )
    return written


def load_artifact_state(workspace: Path) -> dict[str, Any] | None:
    path = artifacts_dir(workspace) / MANIFEST_OF_ARTIFACTS
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


@dataclass(frozen=True)
class DriftReport:
    rendered: bool
    manifest_changed: bool
    tampered: list[str] = field(default_factory=list)
    review_diverged: list[str] = field(default_factory=list)
    stale_masks: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return (
            self.rendered
            and not self.manifest_changed
            and not self.tampered
            and not self.review_diverged
        )


def detect_drift(manifest: Manifest, config: GlobalConfig, workspace: Path) -> DriftReport:
    """Compare on-disk artifacts against what the manifest says they should be."""
    state = load_artifact_state(workspace)
    if state is None:
        return DriftReport(rendered=False, manifest_changed=True)

    expected_digest = manifest_digest(manifest, config)
    tampered: list[str] = []
    review_diverged: list[str] = []
    target_dir = artifacts_dir(workspace)
    review_dir = paths.devcontainer_dir(workspace)

    for name, expected_hash in (state.get("hashes") or {}).items():
        path = target_dir / name
        if not path.is_file():
            tampered.append(name)
            continue
        if sha256_text(path.read_text(encoding="utf-8")) != expected_hash:
            tampered.append(name)
        review = review_dir / name
        if (
            name != ARTIFACT_MCP
            and review.is_file()
            and sha256_text(review.read_text(encoding="utf-8")) != expected_hash
        ):
            review_diverged.append(name)

    stale = stale_masks(
        workspace, merged_masks(manifest, config), state.get("masked_paths") or []
    )
    return DriftReport(
        rendered=True,
        manifest_changed=state.get("digest") != expected_digest,
        tampered=tampered,
        review_diverged=review_diverged,
        stale_masks=stale,
    )


def clean(workspace: Path, *, workspace_copy: bool = True) -> list[Path]:
    """Remove generated artifacts. Used by ``abox nuke``."""
    removed: list[Path] = []
    target_dir = artifacts_dir(workspace)
    if target_dir.exists():
        for path in sorted(target_dir.iterdir()):
            path.unlink(missing_ok=True)
            removed.append(path)
    if workspace_copy:
        review_dir = paths.devcontainer_dir(workspace)
        if review_dir.exists():
            for name in (
                ARTIFACT_DEVCONTAINER,
                ARTIFACT_DOCKERFILE,
                ARTIFACT_FIREWALL,
                ".abox-generated",
            ):
                path = review_dir / name
                if path.exists():
                    path.unlink()
                    removed.append(path)
            if not any(review_dir.iterdir()):
                review_dir.rmdir()
    return removed


def inspect_rendered(workspace: Path) -> dict[str, Any]:
    """Load the runspec — the argv abox will actually run."""
    path = artifacts_dir(workspace) / ARTIFACT_RUNSPEC
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def runspec_path(workspace: Path) -> Path:
    return artifacts_dir(workspace) / ARTIFACT_RUNSPEC


def artifacts_dir_is_private(workspace: Path) -> bool:
    """The artifacts dir is mounted read-only, but a group/world-writable source
    would let anything else on the host swap the script abox is about to trust."""
    mode = artifacts_dir(workspace).stat().st_mode
    return not (mode & 0o077)
