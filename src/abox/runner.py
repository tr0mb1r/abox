"""``abox run`` / ``abox shell`` — provision, execute, harvest, dispose.

The sequence is fixed and every step is a gate for the next:

1. Preflight the boundaries. ``bypassPermissions`` is refused unless the sandbox
   that justifies it is provably present.
2. ``docker run`` a fresh container from the runspec abox rendered.
3. Confirm the firewall actually came up **inside** the container before any
   model-influenced code runs. The firewall script writes a marker into the
   bind-mounted log dir; no marker, no run.
4. ``docker exec claude -p …`` with the transcript teed to disk.
5. Harvest iptables counters and the dnsmasq log, then destroy the container.

Step 3 is the one that most repays paranoia: a container whose ``postStart``
firewall silently failed looks identical from the host to one where it worked.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import dockerx, gateway, paths, render, shell, telemetry
from .catalog import Catalog
from .errors import AboxError, BoundaryError, HostToolError
from .manifest import GlobalConfig, Manifest, PermissionMode, effective_allowlist

FIREWALL_MARKER = "firewall-ok"
BUILD_TIMEOUT = 3600


@dataclass
class Provisioned:
    """A live agent container plus the facts abox needs about it."""

    run_id: str
    container_id: str
    container_name: str
    workspace: Path
    config_path: Path
    remote_user: str = "vscode"
    warnings: list[str] = field(default_factory=list)


@dataclass
class RunOutcome:
    run_id: str
    exit_code: int
    duration_s: float
    transcript: Path | None
    session_id: str = ""
    container: str = ""
    denied: list[telemetry.DeniedDomain] = field(default_factory=list)
    counters: telemetry.FirewallCounters | None = None
    tool_calls: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


# -- boundary gate --------------------------------------------------------


@dataclass
class BoundaryCheck:
    name: str
    ok: bool
    detail: str

    def __str__(self) -> str:
        return f"{'ok ' if self.ok else 'FAIL'} {self.name}: {self.detail}"


def boundary_checks(
    manifest: Manifest, config: GlobalConfig, workspace: Path
) -> list[BoundaryCheck]:
    """Static checks on the rendered config — run before the container exists."""
    checks: list[BoundaryCheck] = []
    rendered = render.inspect_rendered(workspace)

    if not rendered:
        checks.append(BoundaryCheck("artifacts", False, "no rendered runspec"))
        return checks

    run_args = " ".join(rendered.get("run_args") or [])
    checks.append(
        BoundaryCheck(
            "capabilities",
            "NET_ADMIN" in run_args and "NET_RAW" in run_args,
            "NET_ADMIN and NET_RAW are required for the firewall",
        )
    )
    checks.append(
        BoundaryCheck(
            "network",
            config.network in run_args,
            f"agent must join {config.network}",
        )
    )

    sock = [a for a in (rendered.get("run_args") or []) if "docker.sock" in str(a)]
    checks.append(
        # Precisely: the agent's own argv carries no socket bind. That is not the
        # same as "the agent cannot reach the daemon" — it holds a token for the
        # gateway, which does mount the socket. See the trust-assumptions table.
        BoundaryCheck("no-docker-sock", not sock, "agent runspec must mount no docker socket")
    )

    published = [
        a
        for a in (rendered.get("run_args") or [])
        if str(a) in ("-p", "--publish") or str(a).startswith("--publish=")
    ]
    checks.append(
        BoundaryCheck("no-published-ports", not published, "agent must publish nothing")
    )

    firewall = render.artifacts_dir(workspace) / render.ARTIFACT_FIREWALL
    checks.append(
        BoundaryCheck("firewall-script", firewall.is_file(), f"expected at {firewall}")
    )
    checks.append(
        BoundaryCheck(
            "artifacts-private",
            render.artifacts_dir_is_private(workspace),
            "the mounted artifacts dir must not be group/world accessible",
        )
    )

    drift = render.detect_drift(manifest, config, workspace)
    checks.append(
        BoundaryCheck(
            "artifacts-current",
            not drift.manifest_changed and not drift.tampered,
            "rendered artifacts must match the manifest"
            + (f" (tampered: {', '.join(drift.tampered)})" if drift.tampered else ""),
        )
    )
    return checks


def enforce_boundaries(
    manifest: Manifest, config: GlobalConfig, workspace: Path, *, strict: bool | None = None
) -> list[BoundaryCheck]:
    """Raise if the sandbox does not match what the manifest claims.

    ``strict`` defaults to "whatever ``permission_mode`` demands": a run that
    asks the model to act without prompting gets no benefit of the doubt.
    """
    checks = boundary_checks(manifest, config, workspace)
    failed = [c for c in checks if not c.ok]
    if not failed:
        return checks
    demanding = manifest.run.requires_boundary_gate if strict is None else strict
    if demanding:
        detail = "\n".join(f"  - {c.name}: {c.detail}" for c in failed)
        raise BoundaryError(
            f"refusing to run with permission_mode="
            f"{manifest.run.permission_mode.value} — boundary checks failed:\n{detail}",
            hint="run `abox up` to re-render, or lower run.permission_mode in agentbox.yaml",
        )
    return checks


def verify_firewall_live(container: str, *, required: bool) -> BoundaryCheck:
    """Read the firewall marker from inside the container, as root.

    Deliberately not from a shared directory: the marker is the evidence the
    boundary gate rests on, so the agent must not be able to author it.
    """
    result = dockerx.docker(
        "exec", "-u", "root", container, "cat", f"/var/log/abox/{FIREWALL_MARKER}", timeout=30
    )
    if result.ok and result.stdout.strip():
        body = result.stdout.strip().splitlines()
        summary = ", ".join(body[1:]) if len(body) > 1 else "active"
        return BoundaryCheck("firewall-live", True, summary)
    check = BoundaryCheck(
        "firewall-live",
        False,
        f"the container did not report a working firewall (no {FIREWALL_MARKER})",
    )
    if required:
        raise BoundaryError(
            "the sandbox firewall did not come up; refusing to start the agent",
            hint=f"`docker exec -u root {container} cat /var/log/abox/firewall.log`",
        )
    return check


# -- provisioning ---------------------------------------------------------


def _custom_servers(manifest: Manifest) -> dict[str, Any]:
    from .manifest import CustomServers

    custom = CustomServers.load()
    return {n: custom.servers[n] for n in manifest.servers if n in custom.servers}


def load_runspec(workspace: Path) -> dict[str, Any]:
    spec = render.inspect_rendered(workspace)
    if not spec:
        raise AboxError(
            "no runspec rendered for this project",
            hint="run `abox up` first",
        )
    return spec


def build(
    manifest: Manifest,
    workspace: Path,
    _config_path: Path | None = None,
    *,
    no_cache: bool = False,
    on_line: Any = None,
) -> shell.Result:
    """``docker build`` the agent image.

    The build context is the artifacts directory, not the workspace: nothing from
    the project is copied into the image, so a build cannot be influenced by the
    repository it is about to sandbox.
    """
    runspec = load_runspec(workspace)
    context = render.artifacts_dir(workspace)
    argv = [
        "docker",
        "build",
        "-t",
        runspec["image"],
        "-f",
        str(context / render.ARTIFACT_DOCKERFILE),
    ]
    for key, value in (runspec.get("build", {}).get("args") or {}).items():
        argv += ["--build-arg", f"{key}={value}"]
    if no_cache:
        argv.append("--no-cache")
    argv.append(str(context))
    return shell.run(
        argv, timeout=BUILD_TIMEOUT, stream=bool(on_line), on_line=on_line, cwd=workspace
    )


def image_present(workspace: Path) -> bool:
    return dockerx.image_present(load_runspec(workspace)["image"])


def up(
    manifest: Manifest,
    workspace: Path,
    _config_path: Path | None = None,
    *,
    run_id: str,
    on_line: Any = None,
) -> Provisioned:
    """Create a fresh container for this run and bring its firewall up.

    Everything here is abox's own ``docker run`` argv, taken verbatim from the
    runspec ``doctor`` audits. There is no intermediate tool that could quietly
    reinterpret a capability, a mount, or a network.
    """
    runspec = load_runspec(workspace)
    telemetry.reset_current_run(workspace)
    container = paths.agent_container(manifest.project, run_id)
    dockerx.remove(container)

    if not dockerx.image_present(runspec["image"]):
        raise AboxError(
            f"agent image {runspec['image']} has not been built",
            hint="run `abox up`",
        )

    argv = [
        "docker",
        "run",
        "-d",
        "--name",
        container,
        *runspec["run_args"],
        "--label",
        f"{dockerx.LABEL_RUN}={run_id}",
        runspec["image"],
        # Hold the container open; every command abox runs is an explicit exec.
        "sleep",
        "infinity",
    ]
    result = shell.run(argv, timeout=300, stream=bool(on_line), on_line=on_line)
    if not result.ok:
        detail = shell.first_useful_line(result.stderr or result.stdout)
        raise AboxError(
            f"could not start the agent container: {detail or 'unknown error'}",
            hint=f"docker {' '.join(argv[1:])}",
        )
    container_id = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else container

    provisioned = Provisioned(
        run_id=run_id,
        container_id=container_id,
        container_name=container,
        workspace=workspace,
        config_path=render.runspec_path(workspace),
        remote_user=str(runspec.get("remote_user") or "vscode"),
    )
    _apply_firewall(provisioned, runspec, on_line=on_line)
    return provisioned


def _apply_firewall(
    provisioned: Provisioned, runspec: dict[str, Any], *, on_line: Any = None
) -> None:
    """Run the firewall script as root, through the daemon.

    Not via in-container ``sudo``: the image strips the agent's sudo access
    entirely, because abox already holds the socket and can do this itself. The
    agent therefore has no path to root at all, not even a narrowed one.
    """
    result = dockerx.docker(
        "exec",
        "-u",
        "root",
        provisioned.container_name,
        "/bin/bash",
        str(runspec.get("firewall") or "/opt/abox/init-firewall.sh"),
        timeout=300,
        stream=bool(on_line),
        on_line=on_line,
    )
    if not result.ok:
        provisioned.warnings.append(
            (result.stderr or result.stdout).strip().splitlines()[-1:][0]
            if (result.stderr or result.stdout).strip()
            else "firewall script failed"
        )


# -- execution ------------------------------------------------------------


def claude_argv(
    manifest: Manifest,
    prompt: str | None,
    *,
    resume: str | None = None,
    continue_last: bool = False,
    extra: list[str] | None = None,
    settings: str = "",
) -> list[str]:
    """Build the in-container ``claude`` invocation.

    ``--strict-mcp-config`` is not optional here: it is what makes "exactly one
    MCP endpoint" true rather than aspirational, by refusing any MCP server the
    agent might find in the workspace or in its own config dir.
    """
    argv = ["claude"]
    if prompt is not None:
        argv += ["-p", prompt]
    if settings:
        argv += ["--settings", settings]
    argv += [
        "--output-format",
        manifest.run.output.value,
        "--permission-mode",
        manifest.run.permission_mode.value,
        "--mcp-config",
        "/opt/abox/mcp.json",
    ]
    if manifest.run.single_mcp_endpoint:
        # Refuses any MCP server the agent might find in the workspace or its
        # own config dir. Dropped only when the manifest opts into connectors,
        # because that is precisely a request for a second source.
        argv.append("--strict-mcp-config")
    if manifest.run.output.value == "stream-json":
        # Claude Code requires --verbose to emit stream-json in print mode.
        argv.append("--verbose")
    if resume:
        argv += ["--resume", resume]
    elif continue_last:
        argv.append("--continue")
    argv += extra or []
    return argv


def exec_in_container(
    manifest: Manifest,
    provisioned: Provisioned,
    argv: list[str],
    *,
    timeout: int,
    on_line: Any = None,
) -> shell.Result:
    full = [
        "docker",
        "exec",
        "-u",
        provisioned.remote_user,
        "-w",
        "/workspace",
        provisioned.container_name,
        *argv,
    ]
    return shell.run(
        full,
        timeout=timeout,
        stream=bool(on_line),
        on_line=on_line,
        cwd=provisioned.workspace,
    )


def interactive_shell(manifest: Manifest, provisioned: Provisioned) -> int:
    """Hand the terminal to the container. Used by ``abox shell``."""
    import subprocess

    full = [
        "docker",
        "exec",
        "-it",
        "-u",
        provisioned.remote_user,
        "-w",
        "/workspace",
        provisioned.container_name,
        "/bin/bash",
        "-l",
    ]
    return subprocess.call(full, cwd=str(provisioned.workspace))


# -- teardown -------------------------------------------------------------


def collect_counters(provisioned: Provisioned) -> telemetry.FirewallCounters:
    """Read iptables counters as root via the daemon, not via in-container sudo.

    The agent's sudoers rule only covers the firewall script, so there is no way
    to ask it nicely — and no reason to, since abox holds the socket.
    """
    result = dockerx.docker(
        "exec",
        "-u",
        "root",
        provisioned.container_id or provisioned.container_name,
        "iptables",
        "-L",
        "OUTPUT",
        "-v",
        "-x",
        "-n",
        timeout=60,
    )
    if not result.ok:
        return telemetry.FirewallCounters(raw=result.stderr.strip())
    return telemetry.parse_iptables_counters(result.stdout)


def harvest_logs(provisioned: Provisioned) -> list[str]:
    """Copy the container's audit trail out before the container is destroyed.

    Read as root through the Docker socket, because the whole point of keeping
    these files out of a bind mount is that the agent cannot reach them.
    """
    target = paths.current_run_dir(provisioned.workspace)
    target.mkdir(parents=True, exist_ok=True)
    collected: list[str] = []
    for name in ("dns.log", "firewall.log", FIREWALL_MARKER, "fw-refresh.log"):
        result = dockerx.docker(
            "exec", "-u", "root", provisioned.container_name,
            "cat", f"/var/log/abox/{name}", timeout=60,
        )
        if not result.ok:
            continue
        (target / name).write_text(result.stdout, encoding="utf-8")
        collected.append(name)
    return collected


def teardown(
    provisioned: Provisioned,
    manifest: Manifest,
    config: GlobalConfig,
    *,
    remove: bool = True,
) -> tuple[telemetry.FirewallCounters, list[telemetry.DnsQuery], list[telemetry.DeniedDomain]]:
    counters = collect_counters(provisioned)
    telemetry.record_counters(provisioned.workspace, provisioned.run_id, counters)
    harvest_logs(provisioned)
    queries = telemetry.collect_dns(provisioned.workspace, provisioned.run_id)
    allow = effective_allowlist(manifest, config)
    denied = telemetry.review_queue(
        provisioned.workspace,
        allow,
        since_run=provisioned.run_id,
        ignored=manifest.egress_ignored,
    )
    if remove:
        dockerx.remove(provisioned.container_id or provisioned.container_name)
    return counters, queries, denied


# -- orchestration --------------------------------------------------------


def run(
    manifest: Manifest,
    config: GlobalConfig,
    workspace: Path,
    catalog: Catalog,
    prompt: str,
    *,
    resume: str | None = None,
    continue_last: bool = False,
    keep: bool = False,
    on_line: Any = None,
    on_event: Any = None,
) -> RunOutcome:
    """The full headless path. Every failure leaves the container removed."""
    workspace = workspace.resolve()
    run_id = telemetry.new_run_id()
    started_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    warnings: list[str] = []

    enforce_boundaries(manifest, config, workspace)

    spec = gateway.build_spec(
        manifest.profile,
        config,
        servers=manifest.servers,
        tools=sorted({t for tools in manifest.tools.values() for t in tools}),
        remote_servers=manifest.remote_servers,
        custom_servers=_custom_servers(manifest),
    )
    # The agent gets its endpoint and bearer token from the rendered mcp.json.
    # If the token was re-minted or the port moved since the last render, the
    # agent would come up with no working MCP at all — catch it here rather
    # than as a confusing 401 in the middle of a session.
    rendered_mcp = render.artifacts_dir(workspace) / render.ARTIFACT_MCP
    if rendered_mcp.is_file():
        current = json.loads(rendered_mcp.read_text(encoding="utf-8"))
        expected = gateway.mcp_config(spec)
        if current != expected:
            raise AboxError(
                "the rendered MCP config no longer matches the gateway "
                f"(profile {manifest.profile!r})",
                hint="run `abox up` to re-render — the endpoint or its token changed",
            )

    status = gateway.status(manifest.profile, config)
    if not status.ok:
        raise AboxError(
            f"gateway for profile {manifest.profile!r} is not healthy: {status.detail}",
            hint="run `abox gateway up` (or `abox up`) first",
        )

    provisioned = up(manifest, workspace, run_id=run_id, on_line=on_line)

    transcript = telemetry.transcript_path(workspace, run_id, started_ts)
    started = time.monotonic()
    exit_code = 1
    try:
        firewall = verify_firewall_live(
            provisioned.container_name,
            required=manifest.run.permission_mode is not PermissionMode.plan,
        )
        if not firewall.ok:
            warnings.append(firewall.detail)

        argv = claude_argv(
            manifest,
            prompt,
            resume=resume,
            continue_last=continue_last,
            settings=str(load_runspec(workspace).get("settings") or ""),
        )
        with transcript.open("w", encoding="utf-8") as fh:

            def sink(line: str) -> None:
                fh.write(line + "\n")
                fh.flush()
                if on_event:
                    on_event(line)

            result = exec_in_container(
                manifest, provisioned, argv, timeout=manifest.run.timeout, on_line=sink
            )
        exit_code = result.returncode
        if result.stderr.strip():
            warnings.append(result.stderr.strip().splitlines()[-1][:300])
    finally:
        counters, _queries, denied = teardown(provisioned, manifest, config, remove=not keep)

    transcript.chmod(0o600)
    session_id = telemetry.session_id_from_transcript(transcript)
    tool_calls = telemetry.tool_calls_from_transcript(transcript)
    duration = time.monotonic() - started

    telemetry.record_run(
        workspace,
        telemetry.RunRecord(
            id=run_id,
            ts=started_ts,
            project=manifest.project,
            profile=manifest.profile,
            prompt_sha=telemetry.prompt_digest(prompt),
            duration_s=round(duration, 2),
            exit_code=exit_code,
            session_id=session_id,
            container=provisioned.container_name,
            transcript=str(transcript),
            permission_mode=manifest.run.permission_mode.value,
            servers=list(manifest.servers),
            denied_domains=len(denied),
            dropped_packets=counters.dropped_packets,
            notes=warnings,
        ),
    )
    return RunOutcome(
        run_id=run_id,
        exit_code=exit_code,
        duration_s=duration,
        transcript=transcript,
        session_id=session_id,
        container=provisioned.container_name,
        denied=denied,
        counters=counters,
        tool_calls=tool_calls,
        warnings=warnings,
    )


def shell_session(
    manifest: Manifest,
    config: GlobalConfig,
    workspace: Path,
    *,
    keep: bool = False,
    on_line: Any = None,
) -> RunOutcome:
    """Same provisioning as ``run``, but hands over an interactive tty."""
    workspace = workspace.resolve()
    run_id = telemetry.new_run_id()
    started_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    enforce_boundaries(manifest, config, workspace, strict=False)
    provisioned = up(manifest, workspace, run_id=run_id, on_line=on_line)

    started = time.monotonic()
    warnings: list[str] = []
    try:
        firewall = verify_firewall_live(provisioned.container_name, required=False)
        if not firewall.ok:
            warnings.append(firewall.detail)
        exit_code = interactive_shell(manifest, provisioned)
    finally:
        counters, _queries, denied = teardown(provisioned, manifest, config, remove=not keep)

    duration = time.monotonic() - started
    telemetry.record_run(
        workspace,
        telemetry.RunRecord(
            id=run_id,
            ts=started_ts,
            project=manifest.project,
            profile=manifest.profile,
            prompt_sha="interactive",
            duration_s=round(duration, 2),
            exit_code=exit_code,
            container=provisioned.container_name,
            permission_mode="interactive",
            servers=list(manifest.servers),
            denied_domains=len(denied),
            dropped_packets=counters.dropped_packets,
            notes=warnings,
        ),
    )
    return RunOutcome(
        run_id=run_id,
        exit_code=exit_code,
        duration_s=duration,
        transcript=None,
        container=provisioned.container_name,
        denied=denied,
        counters=counters,
        warnings=warnings,
    )


def require_host_tools() -> list[str]:
    """Report which host tools are missing rather than failing on the first.

    The list is deliberately one item long: Docker. abox drives it directly, so
    there is no Node, no npm, and no @devcontainers/cli anywhere in the chain.
    """
    missing: list[str] = []
    for tool in ("docker",):
        try:
            shell.require_tool(tool)
        except HostToolError:
            missing.append(tool)
    return missing
