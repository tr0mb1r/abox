"""Secret plumbing: pluggable sources, stdin-only transport, salted digests."""

from __future__ import annotations

from pathlib import Path

import pytest

from abox import secrets
from abox.errors import SecretsError
from abox.manifest import SecretMapping, SecretsConfig, SecretSource

SECRET_LS = "docker/mcp/brave.api_key                | docker-pass\n"


def _write_secret_file(path: Path, value: str, mode: int = 0o600) -> Path:
    path.write_text(value)
    path.chmod(mode)
    return path


# -- transport invariants -------------------------------------------------


def test_value_reaches_docker_over_stdin_never_argv(runner, tmp_path: Path) -> None:
    """The single most important property in this module."""
    secrets.docker_secret_set("demo.token", "s3cr3t-value")
    call = runner.find("docker mcp secret set")[0]
    assert call.stdin_data == "s3cr3t-value"
    assert "s3cr3t-value" not in runner.argv_blob


def test_sync_never_puts_a_value_in_argv(runner, tmp_path: Path) -> None:
    runner.expect(r"docker mcp secret ls", SECRET_LS)
    path = _write_secret_file(tmp_path / "tok", "top-secret")
    config = SecretsConfig(mappings=[SecretMapping(secret="demo.token", file=str(path))])
    secrets.sync(config)
    assert "top-secret" not in runner.argv_blob


# -- digests --------------------------------------------------------------


def test_digest_is_salted_not_a_bare_sha256() -> None:
    import hashlib

    value = "hunter2"
    assert secrets.digest(value) != hashlib.sha256(value.encode()).hexdigest()


def test_digest_is_stable_within_an_install() -> None:
    assert secrets.digest("x") == secrets.digest("x")


def test_salt_file_is_private() -> None:
    secrets.digest("x")
    assert secrets.salt_path().stat().st_mode & 0o077 == 0


# -- file source ----------------------------------------------------------


def test_file_source_refuses_world_readable(tmp_path: Path) -> None:
    path = _write_secret_file(tmp_path / "loose", "v", mode=0o644)
    with pytest.raises(SecretsError, match="readable by group or others"):
        secrets.read_from_file(str(path))


def test_file_source_accepts_private(tmp_path: Path) -> None:
    path = _write_secret_file(tmp_path / "tight", "v")
    assert secrets.read_from_file(str(path)) == "v"


def test_file_source_can_be_forced(tmp_path: Path) -> None:
    path = _write_secret_file(tmp_path / "loose", "v", mode=0o644)
    assert secrets.read_from_file(str(path), allow_loose_perms=True) == "v"


def test_file_source_strips_the_trailing_newline(tmp_path: Path) -> None:
    path = _write_secret_file(tmp_path / "tok", "value\n")
    assert secrets.read_from_file(str(path)) == "value"


def test_missing_file_explains_how_to_make_one(tmp_path: Path) -> None:
    with pytest.raises(SecretsError, match="not found") as exc:
        secrets.read_from_file(str(tmp_path / "nope"))
    assert "chmod 600" in (exc.value.hint or "")


# -- env source -----------------------------------------------------------


def test_env_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABOX_TEST_TOKEN", "from-env")
    assert secrets.read_from_env("ABOX_TEST_TOKEN") == "from-env"


def test_env_source_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ABOX_TEST_TOKEN", raising=False)
    with pytest.raises(SecretsError, match="not set"):
        secrets.read_from_env("ABOX_TEST_TOKEN")


# -- op source ------------------------------------------------------------


def test_op_absence_is_not_fatal_for_other_sources(runner, tmp_path, monkeypatch) -> None:
    """A host with no 1Password CLI must still sync file and env sources."""
    monkeypatch.setattr(secrets, "op_available", lambda: False)
    monkeypatch.setenv("ABOX_TEST_TOKEN", "e")
    runner.expect(r"docker mcp secret ls", SECRET_LS)
    path = _write_secret_file(tmp_path / "tok", "f")
    config = SecretsConfig(
        mappings=[
            SecretMapping(secret="a.file", file=str(path)),
            SecretMapping(secret="b.env", env="ABOX_TEST_TOKEN"),
            SecretMapping(secret="c.op", op="op://v/i/f"),
        ]
    )
    reports = {r.name: r for r in secrets.sync(config)}
    assert reports["a.file"].ok
    assert reports["b.env"].ok
    assert reports["c.op"].status is secrets.SecretStatus.unreadable
    assert "op` CLI is not installed" in reports["c.op"].detail


def test_op_read_uses_no_newline(runner, monkeypatch) -> None:
    monkeypatch.setattr(secrets, "op_available", lambda: True)
    runner.expect(r"op read", "value")
    assert secrets.read_from_op("op://v/i/f") == "value"
    assert "--no-newline" in runner.find("op read")[0].argv


# -- docker-managed source ------------------------------------------------


def test_docker_source_is_verified_not_written(runner) -> None:
    runner.expect(r"docker mcp secret ls", SECRET_LS)
    config = SecretsConfig(
        mappings=[SecretMapping(secret="brave.api_key", source=SecretSource.docker)]
    )
    reports = secrets.sync(config)
    assert reports[0].status is secrets.SecretStatus.external
    assert reports[0].ok
    assert not runner.find("docker mcp secret set")


def test_docker_source_missing_from_store_is_reported(runner) -> None:
    runner.expect(r"docker mcp secret ls", SECRET_LS)
    config = SecretsConfig(
        mappings=[SecretMapping(secret="absent.key", source=SecretSource.docker)]
    )
    assert secrets.sync(config)[0].status is secrets.SecretStatus.missing_in_store


# -- prompt source --------------------------------------------------------


def test_prompt_source_is_skipped_in_scripted_sync(runner) -> None:
    runner.expect(r"docker mcp secret ls", SECRET_LS)
    config = SecretsConfig(
        mappings=[SecretMapping(secret="typed.key", source=SecretSource.prompt)]
    )
    report = secrets.sync(config)[0]
    assert "abox secrets set typed.key" in report.detail


# -- sync / check statuses ------------------------------------------------


def test_sync_creates_then_reports_unchanged(runner, tmp_path: Path) -> None:
    path = _write_secret_file(tmp_path / "tok", "v1")
    config = SecretsConfig(mappings=[SecretMapping(secret="demo.token", file=str(path))])

    runner.expect(r"docker mcp secret ls", SECRET_LS)
    assert secrets.sync(config)[0].status is secrets.SecretStatus.created

    runner.responses.clear()
    runner.expect(r"docker mcp secret ls", SECRET_LS + "docker/mcp/demo.token | docker-pass\n")
    assert secrets.sync(config)[0].status is secrets.SecretStatus.unchanged


def test_check_detects_a_rotated_source(runner, tmp_path: Path) -> None:
    path = _write_secret_file(tmp_path / "tok", "v1")
    config = SecretsConfig(mappings=[SecretMapping(secret="demo.token", file=str(path))])
    runner.expect(r"docker mcp secret ls", SECRET_LS)
    secrets.sync(config)

    runner.responses.clear()
    runner.expect(r"docker mcp secret ls", SECRET_LS + "docker/mcp/demo.token | docker-pass\n")
    _write_secret_file(path, "v2")
    report = secrets.check(config)[0]
    assert report.status is secrets.SecretStatus.drifted
    assert "changed since last sync" in report.detail


def test_check_reports_required_but_unmapped(runner) -> None:
    runner.expect(r"docker mcp secret ls", SECRET_LS)
    reports = secrets.check(SecretsConfig(), required=["github.personal_access_token"])
    assert reports[0].status is secrets.SecretStatus.unmapped
    assert not reports[0].ok


def test_check_accepts_a_required_secret_already_in_the_store(runner) -> None:
    runner.expect(r"docker mcp secret ls", SECRET_LS)
    reports = secrets.check(SecretsConfig(), required=["brave.api_key"])
    assert reports[0].status is secrets.SecretStatus.external
    assert reports[0].ok


def test_dry_run_writes_nothing(runner, tmp_path: Path) -> None:
    path = _write_secret_file(tmp_path / "tok", "v1")
    config = SecretsConfig(mappings=[SecretMapping(secret="demo.token", file=str(path))])
    secrets.sync(config, dry_run=True)
    assert not runner.find("docker mcp secret set")
    assert not secrets.state_path().exists()


def test_dry_run_sees_a_secret_deleted_from_the_store(runner, tmp_path: Path) -> None:
    """The preview used to be computed from the digest ledger alone, so a secret
    someone had removed from the store previewed as `unchanged` — the operator
    skipped the real sync and the container failed to start."""
    path = _write_secret_file(tmp_path / "tok", "v1")
    config = SecretsConfig(mappings=[SecretMapping(secret="demo.token", file=str(path))])
    runner.expect(r"docker mcp secret ls", SECRET_LS)
    assert secrets.sync(config)[0].status is secrets.SecretStatus.created

    # The value is unchanged, but the store no longer has it.
    report = secrets.sync(config, dry_run=True)[0]
    assert report.status is secrets.SecretStatus.created
    assert len(runner.find("docker mcp secret set demo.token")) == 1  # the real sync only


def test_dry_run_does_not_fail_a_healthy_external_mapping(runner) -> None:
    """The false-red half: a `source: docker` mapping that is present and a
    `source: prompt` one already in the store previewed as not-ok, so a scripted
    `--dry-run` pre-flight failed on a perfectly good install."""
    runner.expect(
        r"docker mcp secret ls",
        "docker/mcp/ext.tok | docker-pass\ndocker/mcp/typed.tok | docker-pass\n",
    )
    config = SecretsConfig(
        mappings=[
            SecretMapping(secret="ext.tok", source=SecretSource.docker),
            SecretMapping(secret="typed.tok", source=SecretSource.prompt),
        ]
    )
    reports = {r.name: r for r in secrets.sync(config, dry_run=True)}
    assert reports["ext.tok"].status is secrets.SecretStatus.external
    assert reports["typed.tok"].status is secrets.SecretStatus.unchanged
    assert all(r.ok for r in reports.values())


def test_a_failed_write_keeps_the_digests_already_written(runner, tmp_path: Path) -> None:
    """Digests lived in memory until the loop ended, so a daemon failure on the
    second secret lost the first one's — and every later `secrets check`
    reported drift on a credential that was exactly current."""
    a = _write_secret_file(tmp_path / "a", "1")
    b = _write_secret_file(tmp_path / "b", "2")
    runner.expect(r"docker mcp secret ls", SECRET_LS)
    runner.expect(r"docker mcp secret set b.key", "", returncode=1, stderr="daemon busy")
    config = SecretsConfig(
        mappings=[
            SecretMapping(secret="a.key", file=str(a)),
            SecretMapping(secret="b.key", file=str(b)),
        ]
    )
    with pytest.raises(SecretsError, match=r"b\.key"):
        secrets.sync(config)
    assert runner.find("docker mcp secret set a.key")
    assert secrets.SyncState.load().digest_of("a.key") == secrets.digest("1")


def test_only_filters_the_sync(runner, tmp_path: Path) -> None:
    runner.expect(r"docker mcp secret ls", SECRET_LS)
    a = _write_secret_file(tmp_path / "a", "1")
    b = _write_secret_file(tmp_path / "b", "2")
    config = SecretsConfig(
        mappings=[
            SecretMapping(secret="a.key", file=str(a)),
            SecretMapping(secret="b.key", file=str(b)),
        ]
    )
    reports = secrets.sync(config, only=["a.key"])
    assert [r.name for r in reports] == ["a.key"]


def test_state_file_is_private(runner, tmp_path: Path) -> None:
    runner.expect(r"docker mcp secret ls", SECRET_LS)
    path = _write_secret_file(tmp_path / "tok", "v")
    secrets.sync(SecretsConfig(mappings=[SecretMapping(secret="demo.token", file=str(path))]))
    assert secrets.state_path().stat().st_mode & 0o077 == 0


def test_state_file_holds_no_values(runner, tmp_path: Path) -> None:
    runner.expect(r"docker mcp secret ls", SECRET_LS)
    path = _write_secret_file(tmp_path / "tok", "very-secret")
    secrets.sync(SecretsConfig(mappings=[SecretMapping(secret="demo.token", file=str(path))]))
    assert "very-secret" not in secrets.state_path().read_text()


def test_docker_secret_names_strips_the_prefix(runner) -> None:
    runner.expect(r"docker mcp secret ls", SECRET_LS)
    assert secrets.docker_secret_names() == {"brave.api_key"}


# -- secrets handed to the agent -------------------------------------------


def test_env_secrets_reach_the_runspec_as_references_not_values(tmp_path: Path) -> None:
    """abox must never read the value: the daemon resolves `se://` at container
    start, so nothing abox writes to disk can contain a credential."""
    from abox import gateway, render
    from abox.manifest import GlobalConfig, Manifest, ProfileConfig

    workspace = tmp_path / "ws"
    workspace.mkdir()
    config = GlobalConfig(profiles={"dev": ProfileConfig(port=8811)})
    manifest = Manifest(
        project="demo", profile="dev", env_secrets={"GH_TOKEN": "some.token"}
    )
    spec = gateway.build_spec("dev", config, servers=[])
    result = render.render(manifest, config, workspace, spec)
    runspec = result.artifacts[render.ARTIFACT_RUNSPEC]
    assert "GH_TOKEN=se://docker/mcp/some.token" in runspec
    # The reference, never a value — there is nothing here to leak.
    assert "se://" in runspec


def test_env_secrets_reject_reserved_names() -> None:
    from abox.errors import ConfigError
    from abox.manifest import Manifest

    with pytest.raises(ConfigError, match="set by abox itself"):
        Manifest.parse_yaml(
            "project: a\nprofile: b\nenv_secrets:\n  CLAUDE_CONFIG_DIR: some.token\n"
        )


def test_env_secrets_reject_bad_names() -> None:
    from abox.errors import ConfigError
    from abox.manifest import Manifest

    with pytest.raises(ConfigError, match="environment variable name"):
        Manifest.parse_yaml("project: a\nprofile: b\nenv_secrets:\n  'not a var': some.token\n")


def test_doctor_reports_that_the_agent_holds_secrets(runner) -> None:
    from abox import doctor
    from abox.manifest import GlobalConfig, Manifest, ProfileConfig

    runner.expect(r"docker mcp secret ls", "docker/mcp/some.token | docker-pass\n")
    config = GlobalConfig(profiles={"dev": ProfileConfig(port=8811)})
    manifest = Manifest(
        project="demo", profile="dev", env_secrets={"GH_TOKEN": "some.token"}
    )
    checks = {c.id: c for c in doctor.check_agent_secrets(manifest, config)}
    assert checks["agent.env-secrets"].status is doctor.Status.warn
    assert "GH_TOKEN←some.token" in checks["agent.env-secrets"].detail
    assert "egress" in checks["agent.env-secrets"].hint
    assert checks["agent.env-secrets-present"].status is doctor.Status.ok


def test_doctor_fails_when_an_attached_secret_is_absent(runner) -> None:
    from abox import doctor
    from abox.manifest import GlobalConfig, Manifest, ProfileConfig

    runner.expect(r"docker mcp secret ls", "")
    config = GlobalConfig(profiles={"dev": ProfileConfig(port=8811)})
    manifest = Manifest(project="demo", profile="dev", env_secrets={"X": "absent.token"})
    checks = {c.id: c for c in doctor.check_agent_secrets(manifest, config)}
    assert checks["agent.env-secrets-present"].status is doctor.Status.fail


def test_no_agent_secret_checks_when_none_attached() -> None:
    from abox import doctor
    from abox.manifest import GlobalConfig, Manifest, ProfileConfig

    config = GlobalConfig(profiles={"dev": ProfileConfig(port=8811)})
    assert doctor.check_agent_secrets(Manifest(project="d", profile="dev"), config) == []


# -- the reverse index -----------------------------------------------------


def _bind(workspace: Path, manifest, profile: str = "dev") -> None:
    from abox import gateway

    manifest.write(workspace)
    gateway.bind_project(
        profile,
        workspace=workspace,
        project=manifest.project,
        servers=manifest.servers,
        tools=manifest.tools,
        remote_servers=manifest.remote_servers,
    )


def test_usage_index_covers_all_three_consumption_paths(tmp_path: Path, catalog_file) -> None:
    """A secret reaches a project as an agent env var, as an MCP server's
    requirement, or in a remote server's headers. All three are blast radius."""
    from abox import catalog as catalog_mod
    from abox.manifest import Manifest, RemoteSecret, RemoteServer

    ws = tmp_path / "proj"
    ws.mkdir()
    _bind(
        ws,
        Manifest(
            project="alpha",
            profile="dev",
            servers=["github-official"],
            env_secrets={"DATABASE_URL": "db.url"},
            remote_servers={
                "acme": RemoteServer(
                    url="https://mcp.acme.com/mcp",
                    headers={"Authorization": "Bearer ${ACME}"},
                    secrets=[RemoteSecret(name="acme.key", env="ACME")],
                )
            },
        ),
    )
    index = secrets.usage_index(catalog_mod.load(allow_oci_fallback=False))
    assert [str(u) for u in index["db.url"]] == ["alpha → env DATABASE_URL"]
    assert [str(u) for u in index["acme.key"]] == ["alpha → remote acme"]
    assert [str(u) for u in index["github.personal_access_token"]] == [
        "alpha → server github-official"
    ]


def test_one_secret_shared_by_two_projects_lists_both(tmp_path: Path) -> None:
    """The question worth asking before rotating: who else breaks?"""
    from abox.manifest import Manifest

    for name in ("alpha", "beta"):
        ws = tmp_path / name
        ws.mkdir()
        _bind(ws, Manifest(project=name, profile="dev", env_secrets={"TOKEN": "shared.key"}))
    uses = secrets.usage_index()["shared.key"]
    assert sorted(u.project for u in uses) == ["alpha", "beta"]


def test_unreferenced_secrets_are_absent_from_the_index(tmp_path: Path) -> None:
    from abox.manifest import Manifest

    ws = tmp_path / "proj"
    ws.mkdir()
    _bind(ws, Manifest(project="alpha", profile="dev"))
    assert secrets.usage_index() == {}


def _write_secrets_yaml(body: str) -> Path:
    from abox import paths

    path = paths.secrets_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def test_a_mapping_that_would_recreate_the_secret_is_in_the_index() -> None:
    """`abox secrets rm` gates on this index. A mapping left in secrets.yaml is
    re-pushed by the very next `abox secrets sync`, so a removal that ignores it
    is not a revocation — it is a revocation that undoes itself."""
    _write_secrets_yaml("mappings:\n  - secret: github.pat\n    op: op://vault/gh/token\n")
    uses = secrets.usage_index()["github.pat"]
    assert [u.kind for u in uses] == ["mapping"]
    assert "op://vault/gh/token" in uses[0].detail
    assert "secrets.yaml" in uses[0].detail


def test_an_externally_managed_mapping_is_not_a_false_refusal() -> None:
    """`source: docker` is the one mapping sync will not re-push, so blocking on
    it would be a standing false refusal that trains you past the gate."""
    _write_secrets_yaml("mappings:\n  - secret: outside.key\n    source: docker\n")
    assert secrets.usage_index() == {}


def test_secrets_rm_refuses_a_secret_still_mapped_in_secrets_yaml(runner) -> None:
    """The gate has to reach the command: the index is `secrets rm`'s only
    refusal surface, so a mapping it cannot see is a mapping it cannot block."""
    from typer.testing import CliRunner

    from abox.cli import app

    runner.expect(r"docker mcp secret ls", "docker/mcp/github.pat | docker-pass\n")
    _write_secrets_yaml("mappings:\n  - secret: github.pat\n    op: op://vault/gh/token\n")

    result = CliRunner().invoke(app, ["secrets", "rm", "github.pat"])
    assert result.exit_code != 0
    assert not runner.find("docker mcp secret rm")
    assert "still referenced by" in result.output

    forced = CliRunner().invoke(app, ["secrets", "rm", "github.pat", "--force"])
    assert forced.exit_code == 0
    assert runner.find("docker mcp secret rm")


def test_a_moved_project_is_reported_as_stale(tmp_path: Path) -> None:
    """A registry entry whose manifest has gone makes the index incomplete, and
    silently incomplete blast radius is worse than none."""
    from abox.manifest import Manifest

    ws = tmp_path / "proj"
    ws.mkdir()
    _bind(ws, Manifest(project="alpha", profile="dev", env_secrets={"T": "k"}))
    assert secrets.stale_projects() == []
    (ws / "agentbox.yaml").unlink()
    assert secrets.stale_projects() == [str(ws)]
    assert secrets.usage_index() == {}


def test_one_broken_manifest_does_not_hide_the_others(tmp_path: Path) -> None:
    from abox.manifest import Manifest

    good = tmp_path / "good"
    good.mkdir()
    _bind(good, Manifest(project="good", profile="dev", env_secrets={"T": "k"}))
    bad = tmp_path / "bad"
    bad.mkdir()
    _bind(bad, Manifest(project="bad", profile="dev"))
    (bad / "agentbox.yaml").write_text("this: is not: valid: yaml: at all\n")
    assert [u.project for u in secrets.usage_index()["k"]] == ["good"]


def test_attribution_never_invents_a_server_name() -> None:
    """A tool no catalog claims must not be bucketed under a fake server: the
    hint would then tell you to narrow something that does not exist."""
    from abox import gateway
    from abox.catalog import Catalog, CatalogServer

    cat = Catalog(servers={"known": CatalogServer(name="known", tools=("a",))})
    grouped = gateway.attribute_tools(
        [{"name": "a"}, {"name": "mystery"}], cat, ["known"]
    )
    assert list(grouped["known"]) == [{"name": "a"}]
    assert grouped[gateway.UNATTRIBUTED] == [{"name": "mystery"}]
    assert gateway.UNATTRIBUTED not in {"known", "mystery"}
