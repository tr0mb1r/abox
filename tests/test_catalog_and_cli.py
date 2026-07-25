"""Catalog parsing, path identity, picker detection, and the CLI surface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from abox import catalog as catalog_mod
from abox import paths, picker
from abox.cli import app
from abox.manifest import CustomServer, CustomServers, Manifest

cli = CliRunner()


# -- catalog --------------------------------------------------------------


def test_local_v3_catalog_is_parsed(catalog_file: Path) -> None:
    cat = catalog_mod.load(allow_oci_fallback=False)
    assert set(cat.names()) == {"github-official", "duckduckgo", "floating"}
    github = cat.require("github-official")
    assert github.secrets == ("github.personal_access_token",)
    assert github.tools == ("list_issues", "create_pull_request")
    assert github.pinned


def test_unpinned_entry_is_detected(catalog_file: Path) -> None:
    assert not catalog_mod.load(allow_oci_fallback=False).require("floating").pinned


def test_custom_servers_shadow_the_catalog(catalog_file: Path) -> None:
    custom = CustomServers(
        servers={"duckduckgo": CustomServer(image="ghcr.io/me/ddg@sha256:" + "c" * 64)}
    )
    cat = catalog_mod.load(custom=custom, allow_oci_fallback=False)
    assert cat.require("duckduckgo").source == "custom"
    assert any("shadows" in w for w in cat.warnings)


def test_custom_to_catalog_carries_the_local_image_flag() -> None:
    """The gateway's pre-pull skips `pin: false` images (they live in no
    registry), so the intent must survive into the catalog. It is distinct from
    the computed `pinned` property: a digest image is pinned and not local; a
    `pin: false` tag is neither."""
    custom = CustomServers(
        servers={
            "signed": CustomServer(image="ghcr.io/me/a@sha256:" + "a" * 64),
            "local": CustomServer(image="a:local", pin=False),
        }
    )
    entries = catalog_mod.custom_to_catalog(custom)
    assert entries["signed"].local_image is False
    assert entries["signed"].pinned is True
    assert entries["local"].local_image is True
    assert entries["local"].pinned is False


def test_secrets_for_collects_across_servers(catalog_file: Path) -> None:
    cat = catalog_mod.load(allow_oci_fallback=False)
    assert cat.secrets_for(["github-official", "duckduckgo"]) == [
        "github.personal_access_token"
    ]


def test_unknown_server_error_points_at_the_fix(catalog_file: Path) -> None:
    from abox.errors import AboxError

    cat = catalog_mod.load(allow_oci_fallback=False)
    with pytest.raises(AboxError, match="unknown MCP server") as exc:
        cat.require("nope")
    assert "custom-servers.yaml" in (exc.value.hint or "")


def test_missing_catalog_dir_warns_rather_than_raising(tmp_path: Path) -> None:
    cat = catalog_mod.load(allow_oci_fallback=False)
    assert cat.names() == []
    assert cat.warnings


# -- paths ----------------------------------------------------------------


def test_project_hash_is_path_derived_and_stable(tmp_path: Path) -> None:
    a = tmp_path / "a"
    a.mkdir()
    assert paths.project_hash(a) == paths.project_hash(a)
    b = tmp_path / "b"
    b.mkdir()
    assert paths.project_hash(a) != paths.project_hash(b)


def test_auth_volume_is_per_project(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    assert paths.claude_volume(a) != paths.claude_volume(b)
    assert paths.claude_volume(a).startswith("abox-claude-")


def test_state_tree_is_private(workspace: Path) -> None:
    root = paths.ensure_project_state(workspace)
    assert root.stat().st_mode & 0o077 == 0
    assert paths.runs_dir(workspace).stat().st_mode & 0o077 == 0


def test_find_workspace_walks_up(workspace: Path) -> None:
    Manifest(project="demo", profile="dev").write(workspace)
    nested = workspace / "src" / "deep"
    nested.mkdir(parents=True)
    assert paths.find_workspace(nested) == workspace.resolve()


def test_find_workspace_falls_back_to_cwd(tmp_path: Path) -> None:
    assert paths.find_workspace(tmp_path) == tmp_path.resolve()


# -- picker detection -----------------------------------------------------


def test_toolchain_detection(workspace: Path) -> None:
    (workspace / "go.mod").write_text("module demo\n")
    assert set(picker.detect_toolchains(workspace)) == {"python", "go"}


def test_egress_suggestions_follow_the_toolchains(workspace: Path) -> None:
    suggested = picker.suggest_egress(["python", "go"], workspace)
    assert "pypi.org" in suggested
    assert "proxy.golang.org" in suggested


def test_git_remotes_are_read_from_the_config_file(workspace: Path) -> None:
    """Never `git remote -v`: running git in a workspace an agent touched would
    execute whatever aliases it planted."""
    (workspace / ".git" / "config").write_text(
        '[remote "origin"]\n\turl = git@github.com:me/repo.git\n'
    )
    assert picker.detect_git_remotes(workspace) == ["github.com"]
    suggested = picker.suggest_egress([], workspace)
    assert {"github.com", "api.github.com", "codeload.github.com"} <= set(suggested)


@pytest.mark.parametrize(
    ("url", "host"),
    [
        ("git@github.com:me/repo.git", "github.com"),
        ("https://gitlab.com/me/repo.git", "gitlab.com"),
        ("ssh://git@bitbucket.org:22/me/repo", "bitbucket.org"),
        ("", ""),
    ],
)
def test_host_from_git_url(url: str, host: str) -> None:
    assert picker._host_from_git_url(url) == host


# -- CLI ------------------------------------------------------------------


def test_version_flag() -> None:
    result = cli.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "abox" in result.stdout


def test_init_writes_a_valid_manifest(tmp_path: Path, catalog_file: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname='x'\n")
    result = cli.invoke(
        app,
        ["init", "--dir", str(project), "--yes", "--server", "duckduckgo"],
    )
    assert result.exit_code == 0, result.stdout
    manifest = Manifest.load(project)
    assert manifest.servers == ["duckduckgo"]
    assert manifest.toolchains == ["python"]
    assert "pypi.org" in manifest.egress


def test_init_is_idempotent(tmp_path: Path, catalog_file: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    args = ["init", "--dir", str(project), "--yes", "--server", "duckduckgo"]
    assert cli.invoke(app, args).exit_code == 0
    first = Manifest.load(project)
    assert cli.invoke(app, args).exit_code == 0
    assert Manifest.load(project) == first


def test_init_renders_the_artifacts(tmp_path: Path, catalog_file: Path) -> None:
    from abox import render

    project = tmp_path / "proj"
    project.mkdir()
    cli.invoke(app, ["init", "--dir", str(project), "--yes"])
    artifacts = render.artifacts_dir(project)
    assert (artifacts / render.ARTIFACT_DEVCONTAINER).is_file()
    assert (artifacts / render.ARTIFACT_FIREWALL).is_file()
    assert (artifacts / render.ARTIFACT_MCP).is_file()


def test_egress_add_updates_the_manifest_and_rerenders(tmp_path: Path, catalog_file: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    cli.invoke(app, ["init", "--dir", str(project), "--yes"])
    result = cli.invoke(app, ["egress", "add", "example.com", "--dir", str(project)])
    assert result.exit_code == 0
    assert "example.com" in Manifest.load(project).egress


def test_egress_add_rejects_a_url(tmp_path: Path, catalog_file: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    cli.invoke(app, ["init", "--dir", str(project), "--yes"])
    result = cli.invoke(app, ["egress", "add", "https://example.com", "--dir", str(project)])
    assert result.exit_code != 0


def test_mcp_add_and_rm(tmp_path: Path, catalog_file: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    cli.invoke(app, ["init", "--dir", str(project), "--yes"])
    assert cli.invoke(app, ["mcp", "add", "duckduckgo", "--dir", str(project)]).exit_code == 0
    assert Manifest.load(project).servers == ["duckduckgo"]
    assert cli.invoke(app, ["mcp", "rm", "duckduckgo", "--dir", str(project)]).exit_code == 0
    assert Manifest.load(project).servers == []


def test_mcp_add_warns_about_required_secrets(tmp_path: Path, catalog_file: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    cli.invoke(app, ["init", "--dir", str(project), "--yes"])
    result = cli.invoke(app, ["mcp", "add", "github-official", "--dir", str(project)])
    assert "github.personal_access_token" in result.stdout


def test_run_without_a_manifest_fails_helpfully(tmp_path: Path) -> None:
    result = cli.invoke(app, ["run", "hi", "--dir", str(tmp_path)])
    assert result.exit_code != 0
    assert "abox init" in (result.output + (result.stderr or ""))


def test_doctor_json_is_parseable(tmp_path: Path, catalog_file: Path, runner) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    cli.invoke(app, ["init", "--dir", str(project), "--yes"])
    result = cli.invoke(app, ["doctor", "--dir", str(project), "--json", "--quick"])
    payload = json.loads(result.stdout)
    assert "checks" in payload
    assert isinstance(payload["ok"], bool)


def test_init_reports_bad_answers_without_a_traceback(tmp_path: Path, catalog_file: Path) -> None:
    """Whatever the picker collects, an invalid combination must come out as an
    abox error, not a raw pydantic ValidationError."""
    project = tmp_path / "proj"
    project.mkdir()
    # init lowercases and de-spaces the project name, so use something it
    # cannot sanitise into validity.
    result = cli.invoke(app, ["init", "--dir", str(project), "--yes", "--project", "my@proj"])
    assert result.exit_code != 0
    assert result.exception is None or isinstance(result.exception, SystemExit)
    combined = result.output + (result.stderr or "")
    assert "Traceback" not in combined
    assert "valid manifest" in combined or "project" in combined


def test_egress_ignore_removes_it_from_the_queue(tmp_path: Path, catalog_file: Path) -> None:
    from abox import paths as abox_paths
    from abox import telemetry

    project = tmp_path / "proj"
    project.mkdir()
    cli.invoke(app, ["init", "--dir", str(project), "--yes"])
    abox_paths.ensure_project_state(project)
    (abox_paths.current_run_dir(project) / "dns.log").write_text(
        "Jul 23 21:00:29 dnsmasq[1]: query[A] telemetry.vendor.io from 172.18.0.3\n"
    )
    telemetry.collect_dns(project, "r1")

    assert cli.invoke(
        app, ["egress", "ignore", "telemetry.vendor.io", "--dir", str(project)]
    ).exit_code == 0
    manifest = Manifest.load(project)
    assert manifest.egress_ignored == ["telemetry.vendor.io"]
    assert telemetry.review_queue(project, [], ignored=manifest.egress_ignored) == []

    assert cli.invoke(
        app, ["egress", "unignore", "telemetry.vendor.io", "--dir", str(project)]
    ).exit_code == 0
    assert Manifest.load(project).egress_ignored == []


# -- host inventory --------------------------------------------------------


def test_host_inventory_classifies_each_source(
    tmp_path: Path, catalog_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The three shapes a host server can take, and what abox can do with each."""
    (tmp_path / "docker-mcp" / "registry.yaml").write_text(
        "registry:\n  duckduckgo:\n    ref: ''\n  not-in-catalog:\n    ref: ''\n"
    )
    claude_json = tmp_path / "claude.json"
    claude_json.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "MCP_DOCKER": {"command": "docker", "args": ["mcp", "gateway", "run"]},
                    "notes": {"command": "notes"},
                    "hosted": {"type": "http", "url": "https://mcp.example.com/mcp"},
                }
            }
        )
    )
    monkeypatch.setenv("ABOX_CLAUDE_CONFIG", str(claude_json))
    cat = catalog_mod.load(allow_oci_fallback=False)
    inventory = {e.name: e for e in catalog_mod.host_inventory(cat)}

    assert inventory["duckduckgo"].importable is True
    assert inventory["not-in-catalog"].importable is False
    # abox *is* the Docker gateway; importing it into itself is meaningless.
    assert inventory["MCP_DOCKER"].importable is False
    assert "already is this gateway" in inventory["MCP_DOCKER"].reason
    # A host stdio binary cannot cross into the sandbox without a hole.
    assert inventory["notes"].importable is False
    assert "host binary" in inventory["notes"].reason
    assert inventory["hosted"].importable is True


def test_mcp_import_lists_and_applies(
    tmp_path: Path, catalog_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "docker-mcp" / "registry.yaml").write_text(
        "registry:\n  duckduckgo:\n    ref: ''\n"
    )
    monkeypatch.setenv("ABOX_CLAUDE_CONFIG", str(tmp_path / "absent.json"))
    project = tmp_path / "proj"
    project.mkdir()
    cli.invoke(app, ["init", "--dir", str(project), "--yes"])

    listed = cli.invoke(app, ["mcp", "import", "--dir", str(project)])
    assert listed.exit_code == 0
    assert "duckduckgo" in listed.stdout
    assert Manifest.load(project).servers == []

    applied = cli.invoke(app, ["mcp", "import", "--dir", str(project), "--apply"])
    assert applied.exit_code == 0
    assert Manifest.load(project).servers == ["duckduckgo"]


def test_secrets_rm_refuses_while_referenced(tmp_path: Path, catalog_file: Path, runner) -> None:
    """The reverse index exists so revocation is not a guess — a container whose
    se:// reference no longer resolves simply will not start."""
    from abox import gateway

    runner.expect(r"docker mcp secret ls", "docker/mcp/live.key | docker-pass\n")
    project = tmp_path / "proj"
    project.mkdir()
    cli.invoke(app, ["init", "--dir", str(project), "--yes"])
    manifest = Manifest.load(project)
    manifest.env_secrets = {"TOKEN": "live.key"}
    manifest.write(project)
    gateway.bind_project(
        manifest.profile, workspace=project, project=manifest.project,
        servers=[], tools={},
    )

    blocked = cli.invoke(app, ["secrets", "rm", "live.key"])
    assert blocked.exit_code != 0
    assert not runner.find("docker mcp secret rm")

    forced = cli.invoke(app, ["secrets", "rm", "live.key", "--force"])
    assert forced.exit_code == 0
    assert runner.find("docker mcp secret rm")


def test_secrets_rm_drops_the_stale_digest(tmp_path: Path, catalog_file: Path, runner) -> None:
    """Leaving the digest would make a later `check` compare against a secret
    that no longer exists."""
    from abox import secrets as secrets_mod

    runner.expect(r"docker mcp secret ls", "docker/mcp/gone.key | docker-pass\n")
    secrets_mod.set_secret("gone.key", "value", reference="test", source="test")
    assert secrets_mod.SyncState.load().digest_of("gone.key")
    assert cli.invoke(app, ["secrets", "rm", "gone.key"]).exit_code == 0
    assert secrets_mod.SyncState.load().digest_of("gone.key") is None
