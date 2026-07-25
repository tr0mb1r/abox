"""Artifact rendering, mask mechanics, and drift detection."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from abox import gateway, paths, render
from abox.manifest import GlobalConfig, Manifest


@pytest.fixture
def spec(config: GlobalConfig) -> gateway.GatewaySpec:
    return gateway.build_spec("dev", config, servers=["duckduckgo"])


def _render(manifest: Manifest, config: GlobalConfig, workspace: Path, spec) -> render.RenderResult:
    return render.render(manifest, config, workspace, spec)


def test_devcontainer_json_is_valid_jsonc(manifest, config, workspace, spec) -> None:
    result = _render(manifest, config, workspace, spec)
    body = result.artifacts[render.ARTIFACT_DEVCONTAINER]
    assert body.lstrip().startswith("//")
    stripped = _strip(body)
    parsed = json.loads(stripped)
    assert parsed["remoteUser"] == "vscode"
    assert parsed["workspaceFolder"] == "/workspace"


def test_rendered_runspec_holds_the_invariants(manifest, config, workspace, spec) -> None:
    """The runspec is the argv abox executes, so the invariants are asserted
    against it rather than against a file some other tool would interpret."""
    result = _render(manifest, config, workspace, spec)
    render.write(result)
    parsed = render.inspect_rendered(workspace)

    run_args = parsed["run_args"]
    joined = " ".join(run_args)
    assert "NET_ADMIN" in joined
    assert "NET_RAW" in joined
    assert config.network in run_args
    assert "privileged" not in joined
    assert "docker.sock" not in joined
    assert not any(a in ("-p", "--publish") or a.startswith("--publish=") for a in run_args)
    # The agent runs as the unprivileged user, never as root.
    assert run_args[run_args.index("--user") + 1] == config.remote_user


def test_masks_cover_glob_matches_and_literals(manifest, config, workspace, spec) -> None:
    result = _render(manifest, config, workspace, spec)
    assert ".env" in result.masked_paths
    assert ".env.local" in result.masked_paths  # the glob expanded
    assert "secrets" in result.masked_paths
    assert ".git/hooks" in result.masked_paths  # from the global defaults

    mounts = " ".join(json.loads(_strip(result.artifacts[render.ARTIFACT_DEVCONTAINER]))["mounts"])
    assert "target=/workspace/.env," in mounts
    assert "readonly" in mounts


def test_directory_masks_use_the_empty_dir(manifest, config, workspace, spec) -> None:
    result = _render(manifest, config, workspace, spec)
    mounts = json.loads(_strip(result.artifacts[render.ARTIFACT_DEVCONTAINER]))["mounts"]
    secrets_mount = next(m for m in mounts if m.endswith("/workspace/secrets,type=bind,readonly"))
    assert str(paths.empty_mask_dir(workspace)) in secrets_mount


def test_literal_mask_applies_even_when_absent(config, workspace, spec) -> None:
    """Mounting an empty file over a path that does not exist yet still shadows
    anything the run creates there."""
    manifest = Manifest(project="d", profile="dev", mounts={"mask": ["future.key"]})
    result = render.render(manifest, config, workspace, spec)
    assert "future.key" in result.masked_paths


def test_stale_masks_are_reported(manifest, config, workspace, spec) -> None:
    render.write(_render(manifest, config, workspace, spec))
    (workspace / ".env.production").write_text("NEW=1\n")
    drift = render.detect_drift(manifest, config, workspace)
    assert ".env.production" in drift.stale_masks


def test_firewall_script_carries_the_full_allowlist(manifest, config, workspace, spec) -> None:
    result = _render(manifest, config, workspace, spec)
    script = result.artifacts[render.ARTIFACT_FIREWALL]
    assert '"github.com"' in script
    assert '"api.anthropic.com"' in script  # injected mandatory entry
    assert f'GATEWAY_HOST="{spec.container}"' in script
    assert f'GATEWAY_PORT="{spec.port}"' in script
    assert "iptables -P OUTPUT DROP" in script


def test_secrets_and_host_paths_stay_out_of_the_workspace(
    manifest, config, workspace, spec
) -> None:
    """mcp.json carries the gateway bearer token; the runspec is full of host
    paths. Neither belongs in a repo."""
    render.write(_render(manifest, config, workspace, spec))
    review = paths.devcontainer_dir(workspace)
    assert (review / render.ARTIFACT_DEVCONTAINER).is_file()
    assert not (review / render.ARTIFACT_MCP).exists()
    assert not (review / render.ARTIFACT_RUNSPEC).exists()


def test_authoritative_artifacts_live_outside_the_workspace(
    manifest, config, workspace, spec
) -> None:
    written = render.write(_render(manifest, config, workspace, spec))
    for path in written.values():
        assert workspace not in path.parents


def test_artifacts_are_written_read_only(manifest, config, workspace, spec) -> None:
    written = render.write(_render(manifest, config, workspace, spec))
    assert written[render.ARTIFACT_FIREWALL].stat().st_mode & 0o222 == 0
    assert written[render.ARTIFACT_DEVCONTAINER].stat().st_mode & 0o222 == 0


def test_re_render_over_read_only_artifacts_succeeds(manifest, config, workspace, spec) -> None:
    render.write(_render(manifest, config, workspace, spec))
    render.write(_render(manifest, config, workspace, spec))  # must not raise
    assert render.detect_drift(manifest, config, workspace).clean


def test_drift_detects_a_tampered_mounted_artifact(manifest, config, workspace, spec) -> None:
    render.write(_render(manifest, config, workspace, spec))
    script = render.artifacts_dir(workspace) / render.ARTIFACT_FIREWALL
    script.chmod(0o600)
    script.write_text(script.read_text() + "\niptables -F\n")
    drift = render.detect_drift(manifest, config, workspace)
    assert render.ARTIFACT_FIREWALL in drift.tampered
    assert not drift.clean


def test_drift_detects_an_edited_review_copy(manifest, config, workspace, spec) -> None:
    render.write(_render(manifest, config, workspace, spec))
    review = paths.devcontainer_dir(workspace) / render.ARTIFACT_FIREWALL
    review.write_text(review.read_text() + "\n# agent was here\n")
    drift = render.detect_drift(manifest, config, workspace)
    assert render.ARTIFACT_FIREWALL in drift.review_diverged
    assert not drift.tampered  # the mounted copy is untouched


def test_drift_detects_a_changed_manifest(manifest, config, workspace, spec) -> None:
    render.write(_render(manifest, config, workspace, spec))
    manifest.egress = [*manifest.egress, "example.com"]
    assert render.detect_drift(manifest, config, workspace).manifest_changed


def test_drift_reports_unrendered(manifest, config, workspace) -> None:
    drift = render.detect_drift(manifest, config, workspace)
    assert drift.rendered is False


def test_artifacts_dir_is_private(manifest, config, workspace, spec) -> None:
    render.write(_render(manifest, config, workspace, spec))
    assert render.artifacts_dir_is_private(workspace)


def test_context_dir_that_does_not_exist_warns(manifest, config, workspace, spec, tmp_path) -> None:
    manifest.mounts.context = [str(tmp_path / "nope")]
    result = render.render(manifest, config, workspace, spec)
    assert any("does not exist" in w for w in result.warnings)


def test_context_dirs_mount_read_only(manifest, config, workspace, spec, tmp_path) -> None:
    ctx = tmp_path / "notes"
    ctx.mkdir()
    manifest.mounts.context = [str(ctx)]
    result = render.render(manifest, config, workspace, spec)
    mounts = json.loads(_strip(result.artifacts[render.ARTIFACT_DEVCONTAINER]))["mounts"]
    assert any(m.endswith("target=/context/notes,type=bind,readonly") for m in mounts)


def test_toolchains_become_dockerfile_stages(manifest, config, workspace, spec) -> None:
    manifest.toolchains = ["python", "go"]
    body = render.render(manifest, config, workspace, spec).artifacts[render.ARTIFACT_DOCKERFILE]
    assert "astral.sh/uv/install.sh" in body
    assert "go.dev/dl/go" in body
    assert "nodejs.org" not in body  # node was not requested


def test_no_toolchain_installs_nothing_extra(manifest, config, workspace, spec) -> None:
    manifest.toolchains = []
    body = render.render(manifest, config, workspace, spec).artifacts[render.ARTIFACT_DOCKERFILE]
    assert "astral.sh" not in body
    assert "go.dev/dl" not in body


def test_claude_code_is_installed_without_npm(manifest, config, workspace, spec) -> None:
    """The whole point of dropping the devcontainer CLI: no npm anywhere."""
    result = _render(manifest, config, workspace, spec)
    body = result.artifacts[render.ARTIFACT_DOCKERFILE]
    assert "downloads.claude.ai/claude-code-releases" in body
    assert "sha256sum -c -" in body          # checksum-verified, like the official installer
    assert "install -m 0755 /tmp/claude /usr/local/bin/claude" in body
    # No npm *invocation* anywhere (the prose comments mention it by name).
    commands = "\n".join(
        line for line in body.splitlines() if not line.lstrip().startswith("#")
    )
    assert not re.search(r"\b(npm|npx|yarn|pnpm)\b", commands)
    assert not re.search(
        r"\b(npm|npx)\b", result.artifacts[render.ARTIFACT_RUNSPEC]
    )


def test_claude_version_is_pinnable(manifest, config, workspace, spec) -> None:
    config.claude_version = "2.1.218"
    body = render.render(manifest, config, workspace, spec).artifacts[render.ARTIFACT_DOCKERFILE]
    assert "ARG CLAUDE_VERSION=2.1.218" in body


def test_devcontainer_json_is_marked_non_authoritative(manifest, config, workspace, spec) -> None:
    body = _render(manifest, config, workspace, spec).artifacts[render.ARTIFACT_DEVCONTAINER]
    assert "CONVENIENCE ARTIFACT" in body
    assert "abox does not read this file" in body


def test_dockerfile_purges_sudo(manifest, config, workspace, spec) -> None:
    """abox applies the firewall as root through the daemon, so the agent needs
    no root at all. The binary is removed rather than defanged: a neutered
    setuid binary is one config mistake away from working again."""
    body = render.render(manifest, config, workspace, spec).artifacts[render.ARTIFACT_DOCKERFILE]
    # The package's prerm refuses without this, warning about lost admin access.
    assert "SUDO_FORCE_REMOVE=yes" in body
    assert "apt-get purge -y sudo" in body
    assert "rm -f /usr/bin/sudo" in body
    assert "rm -rf /etc/sudoers" in body
    # Build-time assertions, so an image that still ships sudo cannot ship —
    # covering both the binary and the package state, because removing the
    # files while dpkg still believes sudo is installed lets a later
    # `apt-get install` of anything that depends on it put sudo back.
    assert "! command -v sudo" in body
    assert '! dpkg -l sudo 2>/dev/null | grep -q "^ii"' in body
    assert "NOPASSWD" not in body
    assert "chmod u-s" not in body


def _strip(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("//"))


def test_mask_over_a_missing_parent_is_skipped_not_fatal(config, workspace, spec, tmp_path) -> None:
    """Docker cannot create a mountpoint under a directory that is not there.
    A bind mount is fixed at container start, so masking `.git/hooks` in a
    non-repo protects nothing — emitting it would only break `docker run`."""
    plain = tmp_path / "not-a-repo"
    plain.mkdir()
    manifest = Manifest(project="d", profile="dev", mounts={"mask": [".git/hooks"]})
    result = render.render(manifest, config, plain, spec)
    mounts = json.loads(result.artifacts[render.ARTIFACT_RUNSPEC])["run_args"]
    assert not any(".git/hooks" in str(a) for a in mounts)
    assert any("nothing to shadow yet" in w for w in result.warnings)
    assert ".git/hooks" not in result.masked_paths


def test_mask_over_an_existing_parent_is_emitted(config, workspace, spec) -> None:
    """`.git` exists in this fixture, so the mask can and must be applied."""
    manifest = Manifest(project="d", profile="dev", mounts={"mask": [".git/hooks"]})
    result = render.render(manifest, config, workspace, spec)
    run_args = json.loads(result.artifacts[render.ARTIFACT_RUNSPEC])["run_args"]
    assert any("/workspace/.git/hooks" in str(a) for a in run_args)
    assert ".git/hooks" in result.masked_paths


def test_mandatory_egress_covers_claude_auth(manifest, config, workspace, spec) -> None:
    """Per Claude Code's documented network requirements. platform.claude.com is
    the one people miss: OAuth refresh goes there for both account types, so a
    working session breaks later without it."""
    result = _render(manifest, config, workspace, spec)
    for host in ("api.anthropic.com", "platform.claude.com", "claude.ai", "claude.com"):
        assert host in result.egress, host
        assert f'"{host}"' in result.artifacts[render.ARTIFACT_FIREWALL]


def test_mandatory_egress_survives_an_operator_supplied_list(
    manifest, config, workspace, spec
) -> None:
    """The case the test above misses, and the one every real host is in.

    `config` in these tests is a default GlobalConfig, whose egress_mandatory
    *is* BASE_MANDATORY_EGRESS. A config.yaml that spells out its own list
    replaces that default — so an install written before abox added
    platform.claude.com kept working until a token needed refreshing, then
    failed inside the container as a bare ENOTFOUND. The base set is unioned in
    regardless now; "mandatory" means mandatory.
    """
    config.defaults.egress_mandatory = ["api.anthropic.com"]
    result = _render(manifest, config, workspace, spec)
    for host in ("api.anthropic.com", "platform.claude.com", "claude.ai", "claude.com"):
        assert host in result.egress, host
        assert f'"{host}"' in result.artifacts[render.ARTIFACT_FIREWALL], host


def test_operator_additions_to_mandatory_egress_still_apply(
    manifest, config, workspace, spec
) -> None:
    """Unioning the base set must not stop the operator adding to it."""
    config.defaults.egress_mandatory = ["proxy.corp.internal"]
    result = _render(manifest, config, workspace, spec)
    assert "proxy.corp.internal" in result.egress
    assert "platform.claude.com" in result.egress


def test_optional_claude_traffic_is_turned_off_not_just_blocked(
    manifest, config, workspace, spec
) -> None:
    """Blocking a host the agent keeps retrying fills the review queue with
    abox's own defaults, which is how a useful signal becomes noise."""
    result = _render(manifest, config, workspace, spec)
    run_args = json.loads(result.artifacts[render.ARTIFACT_RUNSPEC])["run_args"]
    env = " ".join(run_args)
    assert "DISABLE_AUTOUPDATER=1" in env
    assert "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1" in env
    # The single-endpoint invariant, enforced at the app level too.
    assert "ENABLE_CLAUDEAI_MCP_SERVERS=false" in env
    # And the hosts those switches turn off are not silently allowlisted.
    assert "downloads.claude.ai" not in result.egress
    assert "mcp-proxy.anthropic.com" not in result.egress


def test_stale_masks_ignores_unmountable_entries(manifest, config, spec, tmp_path) -> None:
    """`.git/hooks` in a non-repo can never be emitted, so reporting it as
    'unprotected' would be a warning the operator can never clear."""
    plain = tmp_path / "not-a-repo"
    plain.mkdir()
    manifest.mounts.mask = [".git/hooks"]
    render.write(render.render(manifest, config, plain, spec))
    drift = render.detect_drift(manifest, config, plain)
    assert drift.stale_masks == []


# -- token-saving tooling --------------------------------------------------


def test_rtk_is_off_by_default(manifest, config, workspace, spec) -> None:
    """It installs a PreToolUse hook — another program in the agent's command
    path. Reasonable to want, wrong to enable silently."""
    result = _render(manifest, config, workspace, spec)
    assert "rtk" not in result.artifacts[render.ARTIFACT_DOCKERFILE]
    assert json.loads(result.artifacts[render.ARTIFACT_SETTINGS]) == {}
    assert json.loads(result.artifacts[render.ARTIFACT_RUNSPEC])["settings"] == ""


def test_rtk_opt_in_installs_and_hooks(manifest, config, workspace, spec) -> None:
    config.rtk.enabled = True
    result = _render(manifest, config, workspace, spec)
    dockerfile = result.artifacts[render.ARTIFACT_DOCKERFILE]
    assert "releases/download/v" in dockerfile
    # Same supply-chain discipline as the Claude binary.
    assert "sha256sum -c -" in dockerfile
    assert "checksums.txt" in dockerfile
    # Installed as root, before the USER switch, or the install would fail.
    assert dockerfile.index("/usr/local/bin/rtk") < dockerfile.index(
        f"USER {config.remote_user}"
    )
    settings = json.loads(result.artifacts[render.ARTIFACT_SETTINGS])
    hook = settings["hooks"]["PreToolUse"][0]
    assert hook["matcher"] == "Bash"
    assert hook["hooks"][0]["command"] == "rtk hook claude"


def test_settings_are_mounted_read_only_outside_the_workspace(
    manifest, config, workspace, spec
) -> None:
    """The agent must not be able to edit the hooks that wrap its own commands."""
    config.rtk.enabled = True
    result = _render(manifest, config, workspace, spec)
    render.write(result)
    assert json.loads(result.artifacts[render.ARTIFACT_RUNSPEC])["settings"] == (
        "/opt/abox/settings.json"
    )
    assert not (paths.devcontainer_dir(workspace) / render.ARTIFACT_SETTINGS).exists()
    written = render.artifacts_dir(workspace) / render.ARTIFACT_SETTINGS
    assert written.stat().st_mode & 0o222 == 0


def test_the_log_dir_is_not_bind_mounted(manifest, config, workspace, spec) -> None:
    """Docker Desktop does not enforce uid or mode on a bind mount — verified —
    so a shared log dir would let the agent truncate its own audit trail. The
    egress review queue is only worth reading if the agent cannot edit it."""
    result = _render(manifest, config, workspace, spec)
    run_args = json.loads(result.artifacts[render.ARTIFACT_RUNSPEC])["run_args"]
    mounts = [a for a in run_args if "target=" in str(a)]
    assert not any("/var/log/abox" in m for m in mounts)
    assert json.loads(result.artifacts[render.ARTIFACT_RUNSPEC])["logs"] == "/var/log/abox"


def test_the_image_makes_the_log_dir_root_owned(manifest, config, workspace, spec) -> None:
    body = _render(manifest, config, workspace, spec).artifacts[render.ARTIFACT_DOCKERFILE]
    assert "install -d -m 0755 -o root -g root /var/log/abox" in body
    assert "0777 /var/log/abox" not in body


# -- hardening from the adversarial review ---------------------------------


def test_port_80_is_opt_in(manifest, config, workspace, spec) -> None:
    """Plaintext HTTP is rarely needed and is a downgrade path, so the
    allowlist opens 443 only unless the operator asks for more."""
    script = _render(manifest, config, workspace, spec).artifacts[render.ARTIFACT_FIREWALL]
    assert 'EGRESS_PORTS="443"' in script
    config.egress_ports = [80, 443]
    wider = render.render(manifest, config, workspace, spec).artifacts[render.ARTIFACT_FIREWALL]
    assert 'EGRESS_PORTS="80,443"' in wider


def test_dns_is_scoped_to_the_allowlist(manifest, config, workspace, spec) -> None:
    """Arbitrary name resolution is a covert channel that survives default-deny
    egress: the query name itself carries the data."""
    script = _render(manifest, config, workspace, spec).artifacts[render.ARTIFACT_FIREWALL]
    assert 'echo "address=/#/"' in script          # everything else -> NXDOMAIN
    assert 'echo "server=/github.com/' in script   # declared domains still forwarded
    assert 'echo "server=/${GATEWAY_HOST}/' in script
    # The queries are still logged, or the review queue would go blind.
    assert 'echo "log-queries"' in script


def test_scoped_dns_can_be_turned_off(manifest, config, workspace, spec) -> None:
    config.scoped_dns = False
    script = render.render(manifest, config, workspace, spec).artifacts[render.ARTIFACT_FIREWALL]
    assert "address=/#/" not in script
    assert 'echo "server=${UPSTREAM_DNS}"' in script
