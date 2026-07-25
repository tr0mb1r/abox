"""Internet-hosted MCP servers, proxied through the gateway.

The property under test throughout: adding a remote server must not add an MCP
endpoint for the agent. The gateway makes the outbound call, so the agent still
has exactly one endpoint and its firewall never learns the remote host.
"""

from __future__ import annotations

import json

import pytest
import yaml

from abox import catalog as catalog_mod
from abox import doctor, gateway, render
from abox.errors import ConfigError
from abox.manifest import (
    CustomServers,
    GlobalConfig,
    Manifest,
    RemoteSecret,
    RemoteServer,
    RemoteTransport,
)

CONTEXT7 = RemoteServer(url="https://mcp.context7.com/mcp")


# -- schema ---------------------------------------------------------------


def test_remote_server_requires_https() -> None:
    with pytest.raises(ValueError, match="must be https"):
        RemoteServer(url="http://mcp.example.com/mcp")


def test_remote_host_is_extracted() -> None:
    assert RemoteServer(url="https://mcp.context7.com/mcp").host == "mcp.context7.com"
    assert RemoteServer(url="https://user@mcp.example.com:8443/x").host == "mcp.example.com"


def test_headers_must_reference_declared_secrets() -> None:
    with pytest.raises(ValueError, match="undeclared secret env var"):
        RemoteServer(
            url="https://mcp.example.com/mcp",
            headers={"Authorization": "Bearer ${MISSING_TOKEN}"},
        )


def test_headers_may_reference_declared_secrets() -> None:
    server = RemoteServer(
        url="https://mcp.example.com/mcp",
        headers={"Authorization": "Bearer ${EXAMPLE_TOKEN}"},
        secrets=[RemoteSecret(name="example.api_key", env="EXAMPLE_TOKEN")],
    )
    assert server.secrets[0].name == "example.api_key"


def test_remote_and_local_names_cannot_collide() -> None:
    with pytest.raises(ConfigError, match="both declare"):
        Manifest.parse_yaml(
            "project: a\nprofile: b\nservers: [ctx]\n"
            "remote_servers:\n  ctx:\n    url: https://mcp.example.com/mcp\n"
        )


def test_all_servers_covers_both_kinds() -> None:
    manifest = Manifest(
        project="a", profile="b", servers=["duckduckgo"], remote_servers={"ctx": CONTEXT7}
    )
    assert manifest.all_servers == ["duckduckgo", "ctx"]


def test_tools_filter_may_target_a_remote_server() -> None:
    manifest = Manifest.parse_yaml(
        "project: a\nprofile: b\n"
        "remote_servers:\n  ctx:\n    url: https://mcp.context7.com/mcp\n"
        "tools:\n  ctx: [query-docs]\n"
    )
    assert manifest.tools["ctx"] == ["query-docs"]


def test_manifest_with_remotes_round_trips(workspace) -> None:
    manifest = Manifest(
        project="a",
        profile="dev",
        remote_servers={
            "ctx": RemoteServer(
                url="https://mcp.context7.com/mcp",
                transport=RemoteTransport.sse,
                headers={"Authorization": "Bearer ${CTX_TOKEN}"},
                secrets=[RemoteSecret(name="ctx.api_key", env="CTX_TOKEN")],
            )
        },
    )
    manifest.write(workspace)
    assert Manifest.load(workspace) == manifest


# -- catalog ---------------------------------------------------------------


def test_catalog_parses_remote_entries(tmp_path) -> None:
    directory = tmp_path / "docker-mcp" / "catalogs"
    directory.mkdir(parents=True)
    (directory / "docker-mcp.yaml").write_text(
        """
version: 3
name: docker-mcp
registry:
  asana:
    description: Asana remote server.
    title: Asana
    type: remote
    remote:
      transport_type: sse
      url: https://mcp.asana.com/sse
    oauth:
      providers:
        - provider: asana
          secret: asana.personal_access_token
"""
    )
    server = catalog_mod.load(allow_oci_fallback=False).require("asana")
    assert server.is_remote
    assert server.remote_url == "https://mcp.asana.com/sse"
    assert server.remote_transport == "sse"
    assert server.oauth_providers == ("asana",)


def test_remote_servers_count_as_pinned(tmp_path) -> None:
    """There is no digest to pin on a URL; doctor reports the trust story
    separately rather than failing the pinning check."""
    directory = tmp_path / "docker-mcp" / "catalogs"
    directory.mkdir(parents=True)
    (directory / "c.yaml").write_text(
        "version: 3\nname: c\nregistry:\n  r:\n    type: remote\n"
        "    remote:\n      url: https://x.example.com/mcp\n      transport_type: sse\n"
    )
    assert catalog_mod.load(allow_oci_fallback=False).require("r").pinned


# -- gateway wiring --------------------------------------------------------


def test_remote_catalog_matches_the_docker_v3_shape(config: GlobalConfig) -> None:
    path = gateway.write_remote_catalog("dev", {"ctx": CONTEXT7})
    assert path is not None
    parsed = yaml.safe_load(path.read_text())
    assert parsed["version"] == 3
    entry = parsed["registry"]["ctx"]
    assert entry["type"] == "remote"
    assert entry["remote"]["url"] == "https://mcp.context7.com/mcp"
    assert entry["remote"]["transport_type"] == "streamable-http"
    assert path.stat().st_mode & 0o077 == 0


def test_remote_catalog_carries_headers_and_secrets(config: GlobalConfig) -> None:
    server = RemoteServer(
        url="https://mcp.example.com/mcp",
        headers={"Authorization": "Bearer ${EX_TOKEN}"},
        secrets=[RemoteSecret(name="ex.api_key", env="EX_TOKEN")],
    )
    path = gateway.write_remote_catalog("dev", {"ex": server})
    entry = yaml.safe_load(path.read_text())["registry"]["ex"]  # type: ignore[union-attr]
    assert entry["remote"]["headers"] == {"Authorization": "Bearer ${EX_TOKEN}"}
    assert entry["secrets"] == [{"name": "ex.api_key", "env": "EX_TOKEN"}]


def test_remote_catalog_is_removed_when_empty(config: GlobalConfig) -> None:
    gateway.write_remote_catalog("dev", {"ctx": CONTEXT7})
    assert gateway.remote_catalog_path("dev").exists()
    assert gateway.write_remote_catalog("dev", {}) is None
    assert not gateway.remote_catalog_path("dev").exists()


def test_spec_mounts_the_catalog_and_passes_the_flag(config: GlobalConfig) -> None:
    spec = gateway.build_spec(
        "dev", config, servers=["duckduckgo"], remote_servers={"ctx": CONTEXT7}
    )
    opts = " ".join(spec.run_options())
    assert f"{gateway.CONTAINER_CATALOG_DIR}/abox-dev.yaml:ro" in opts
    args = spec.gateway_args()
    assert "--additional-catalog=abox-dev.yaml" in args
    assert "--servers=ctx,duckduckgo" in args


def test_spec_without_remotes_mounts_no_catalog(config: GlobalConfig) -> None:
    spec = gateway.build_spec("dev", config, servers=["duckduckgo"])
    assert gateway.CONTAINER_CATALOG_DIR not in " ".join(spec.run_options())
    assert not any(a.startswith("--additional-catalog") for a in spec.gateway_args())


def test_fingerprint_changes_when_a_remote_url_changes(config: GlobalConfig) -> None:
    a = gateway.build_spec("dev", config, servers=[], remote_servers={"ctx": CONTEXT7})
    b = gateway.build_spec(
        "dev",
        config,
        servers=[],
        remote_servers={"ctx": RemoteServer(url="https://elsewhere.example.com/mcp")},
    )
    assert a.fingerprint() != b.fingerprint()


def test_registry_unions_remote_servers_across_projects() -> None:
    reg = gateway.ProfileRegistry(profile="dev")
    reg.register(
        project_hash="a",
        workspace="/a",
        project="a",
        servers=[],
        tools={},
        remote_servers={"ctx": CONTEXT7},
    )
    reg.register(
        project_hash="b",
        workspace="/b",
        project="b",
        servers=[],
        tools={},
        remote_servers={"other": RemoteServer(url="https://other.example.com/mcp")},
    )
    reg.save()
    loaded = gateway.ProfileRegistry.load("dev").remote_servers()
    assert sorted(loaded) == ["ctx", "other"]
    assert loaded["ctx"].url == "https://mcp.context7.com/mcp"


def test_registry_reports_conflicting_remote_definitions() -> None:
    reg = gateway.ProfileRegistry(profile="dev")
    reg.register(
        project_hash="a", workspace="/a", project="a", servers=[], tools={},
        remote_servers={"ctx": CONTEXT7},
    )
    reg.register(
        project_hash="b", workspace="/b", project="b", servers=[], tools={},
        remote_servers={"ctx": RemoteServer(url="https://impostor.example.com/mcp")},
    )
    assert reg.remote_conflicts() == ["ctx"]


# -- the invariant ---------------------------------------------------------


def test_a_remote_server_adds_no_agent_endpoint(config: GlobalConfig, workspace) -> None:
    manifest = Manifest(project="demo", profile="dev", remote_servers={"ctx": CONTEXT7})
    spec = gateway.build_spec(
        "dev", config, servers=[], remote_servers=manifest.remote_servers
    )
    cfg = gateway.mcp_config(spec)
    assert list(cfg["mcpServers"]) == ["abox-gateway"]


def test_a_remote_host_is_not_added_to_the_agent_firewall(
    config: GlobalConfig, workspace
) -> None:
    """The gateway dials the remote host; the agent must not be able to."""
    manifest = Manifest(project="demo", profile="dev", remote_servers={"ctx": CONTEXT7})
    spec = gateway.build_spec(
        "dev", config, servers=[], remote_servers=manifest.remote_servers
    )
    result = render.render(manifest, config, workspace, spec)
    assert "mcp.context7.com" not in result.artifacts[render.ARTIFACT_FIREWALL]
    assert "mcp.context7.com" not in result.egress


# -- doctor ----------------------------------------------------------------


def test_doctor_reports_the_remote_trust_story(config: GlobalConfig) -> None:
    manifest = Manifest(project="demo", profile="dev", remote_servers={"ctx": CONTEXT7})
    checks = {
        c.id: c for c in doctor.check_remote_servers(manifest, catalog_mod.Catalog(), [])
    }
    assert checks["remote.transport"].status is doctor.Status.ok
    assert checks["remote.trust"].status is doctor.Status.warn
    assert "no digest to pin" in checks["remote.trust"].detail


def test_doctor_is_silent_without_remotes(config: GlobalConfig) -> None:
    manifest = Manifest(project="demo", profile="dev")
    assert doctor.check_remote_servers(manifest, catalog_mod.Catalog(), []) == []


def test_doctor_flags_a_name_that_shadows_the_catalog(config, catalog_file) -> None:
    manifest = Manifest(
        project="demo", profile="dev", remote_servers={"duckduckgo": CONTEXT7}
    )
    cat = catalog_mod.load(allow_oci_fallback=False)
    checks = {c.id: c for c in doctor.check_remote_servers(manifest, cat, [])}
    assert checks["remote.shadowing"].status is doctor.Status.warn
    assert "duckduckgo" in checks["remote.shadowing"].detail


def test_doctor_surfaces_oauth_providers(config, tmp_path) -> None:
    directory = tmp_path / "docker-mcp" / "catalogs"
    directory.mkdir(parents=True)
    (directory / "c.yaml").write_text(
        "version: 3\nname: c\nregistry:\n  asana:\n    type: remote\n"
        "    remote:\n      url: https://mcp.asana.com/sse\n      transport_type: sse\n"
        "    oauth:\n      providers:\n        - provider: asana\n"
    )
    cat = catalog_mod.load(allow_oci_fallback=False)
    manifest = Manifest(project="demo", profile="dev", servers=["asana"])
    checks = {c.id: c for c in doctor.check_remote_servers(manifest, cat, ["asana"])}
    assert "asana" in checks["remote.oauth"].detail
    assert "abox mcp oauth" in checks["remote.oauth"].hint


def test_remote_secrets_are_required_by_doctor(config, runner) -> None:
    runner.expect(r"docker mcp secret ls", "")
    manifest = Manifest(
        project="demo",
        profile="dev",
        remote_servers={
            "ex": RemoteServer(
                url="https://mcp.example.com/mcp",
                headers={"Authorization": "Bearer ${EX_TOKEN}"},
                secrets=[RemoteSecret(name="ex.api_key", env="EX_TOKEN")],
            )
        },
    )
    from abox.manifest import SecretsConfig

    checks = {
        c.id: c
        for c in doctor.check_secrets(manifest, catalog_mod.Catalog(), SecretsConfig())
    }
    assert "ex.api_key" in checks["secrets.present"].detail


def test_catalog_remote_does_not_fail_the_pinning_check(config, tmp_path) -> None:
    directory = tmp_path / "docker-mcp" / "catalogs"
    directory.mkdir(parents=True)
    (directory / "c.yaml").write_text(
        "version: 3\nname: c\nregistry:\n  asana:\n    type: remote\n"
        "    remote:\n      url: https://mcp.asana.com/sse\n      transport_type: sse\n"
    )
    cat = catalog_mod.load(allow_oci_fallback=False)
    manifest = Manifest(project="demo", profile="dev", servers=["asana"])
    checks = {c.id: c for c in doctor.check_servers(manifest, cat, CustomServers(), config)}
    assert checks["servers.pinned"].status is doctor.Status.ok
    assert checks["servers.declared"].status is doctor.Status.ok


# -- claude.ai connectors --------------------------------------------------


def test_connectors_are_off_by_default(config: GlobalConfig, workspace) -> None:
    manifest = Manifest(project="demo", profile="dev")
    assert manifest.run.single_mcp_endpoint is True
    spec = gateway.build_spec("dev", config, servers=[])
    result = render.render(manifest, config, workspace, spec)
    run_args = " ".join(json.loads(result.artifacts[render.ARTIFACT_RUNSPEC])["run_args"])
    assert "ENABLE_CLAUDEAI_MCP_SERVERS=false" in run_args
    assert "mcp-proxy.anthropic.com" not in result.egress


def test_connectors_opt_in_flips_env_and_egress(config: GlobalConfig, workspace) -> None:
    manifest = Manifest.parse_yaml(
        "project: demo\nprofile: dev\nrun:\n  connectors: true\n"
    )
    assert manifest.run.single_mcp_endpoint is False
    spec = gateway.build_spec("dev", config, servers=[])
    result = render.render(manifest, config, workspace, spec)
    run_args = " ".join(json.loads(result.artifacts[render.ARTIFACT_RUNSPEC])["run_args"])
    # The manifest must win over the global default, or the opt-in is a no-op.
    assert "ENABLE_CLAUDEAI_MCP_SERVERS=true" in run_args
    assert "mcp-proxy.anthropic.com" in result.egress
    assert '"mcp-proxy.anthropic.com"' in result.artifacts[render.ARTIFACT_FIREWALL]


def test_connectors_drop_strict_mcp_config() -> None:
    from abox import runner

    off = Manifest(project="d", profile="dev")
    assert "--strict-mcp-config" in runner.claude_argv(off, "x")
    on = Manifest.parse_yaml("project: d\nprofile: dev\nrun:\n  connectors: true\n")
    assert "--strict-mcp-config" not in runner.claude_argv(on, "x")
    assert "--mcp-config" in runner.claude_argv(on, "x")


def test_doctor_stops_claiming_one_endpoint_when_connectors_are_on(workspace) -> None:
    from abox import render as render_mod
    from abox.manifest import ProfileConfig

    config = GlobalConfig(profiles={"dev": ProfileConfig(port=8811)})
    manifest = Manifest.parse_yaml(
        "project: demo\nprofile: dev\nrun:\n  connectors: true\n"
    )
    spec = gateway.build_spec("dev", config, servers=[])
    render_mod.write(render_mod.render(manifest, config, workspace, spec))
    checks = {c.id: c for c in doctor.check_agent_hygiene(workspace, manifest)}
    check = checks["agent.single-mcp-endpoint"]
    assert check.status is doctor.Status.warn
    assert "claude.ai account" in check.detail
    assert "do not pass through the gateway" in check.hint


# -- custom (operator-supplied) image servers ------------------------------


def _custom(**kw):
    from abox.manifest import CustomServer

    return CustomServer(image="ghcr.io/me/thing@sha256:" + "a" * 64, **kw)


def test_custom_servers_reach_the_gateway_catalog(config: GlobalConfig) -> None:
    """The gateway only knows servers that appear in a catalog it can read, so
    without this a custom image is named in --servers and never found."""
    path = gateway.write_abox_catalog("dev", {}, {"mine": _custom()})
    assert path is not None
    entry = yaml.safe_load(path.read_text())["registry"]["mine"]
    assert entry["type"] == "server"
    assert entry["image"].startswith("ghcr.io/me/thing@sha256:")


def test_custom_catalog_carries_secrets_env_command_volumes(config: GlobalConfig) -> None:
    from abox.manifest import ServerSecret

    server = _custom(
        secrets=[ServerSecret(name="my.token", env="MY_TOKEN")],
        env={"MODE": "fast"},
        command=["--db", "/data/x.db"],
        volumes=["mine-data:/data"],
        tools=["only_this"],
    )
    path = gateway.write_abox_catalog("dev", {}, {"mine": server})
    entry = yaml.safe_load(path.read_text())["registry"]["mine"]  # type: ignore[union-attr]
    assert entry["secrets"] == [{"name": "my.token", "env": "MY_TOKEN"}]
    assert entry["env"] == [{"name": "MODE", "value": "fast"}]
    assert entry["command"] == ["--db", "/data/x.db"]
    assert entry["volumes"] == ["mine-data:/data"]
    assert entry["tools"] == [{"name": "only_this"}]


def test_bare_secret_names_get_an_env_var(config: GlobalConfig) -> None:
    """`secrets: [some.token]` is the obvious way to write it."""
    server = _custom(secrets=["some.token"])
    assert server.secrets[0].name == "some.token"
    assert server.secrets[0].env == "SOME_TOKEN"


def test_custom_and_remote_share_one_catalog(config: GlobalConfig) -> None:
    path = gateway.write_abox_catalog("dev", {"ctx": CONTEXT7}, {"mine": _custom()})
    registry = yaml.safe_load(path.read_text())["registry"]  # type: ignore[union-attr]
    assert sorted(registry) == ["ctx", "mine"]
    assert registry["ctx"]["type"] == "remote"
    assert registry["mine"]["type"] == "server"


def test_catalog_is_mounted_when_only_custom_servers_exist(config: GlobalConfig) -> None:
    spec = gateway.build_spec(
        "dev", config, servers=["mine"], custom_servers={"mine": _custom()}
    )
    assert spec.needs_catalog
    assert "--additional-catalog=abox-dev.yaml" in spec.gateway_args()
    assert gateway.CONTAINER_CATALOG_DIR in " ".join(spec.run_options())


def test_fingerprint_changes_when_a_custom_image_changes(config: GlobalConfig) -> None:
    a = gateway.build_spec("dev", config, servers=[], custom_servers={"m": _custom()})
    other = _custom()
    other.image = "ghcr.io/me/thing@sha256:" + "b" * 64
    b = gateway.build_spec("dev", config, servers=[], custom_servers={"m": other})
    assert a.fingerprint() != b.fingerprint()


def test_registry_unions_custom_servers_across_projects() -> None:
    reg = gateway.ProfileRegistry(profile="dev")
    reg.register(
        project_hash="a", workspace="/a", project="a", servers=["m"], tools={},
        custom_servers={"m": _custom()},
    )
    reg.save()
    assert "m" in gateway.ProfileRegistry.load("dev").custom_servers()


def test_doctor_names_the_custom_image_trust_story(config: GlobalConfig) -> None:
    """A custom image outside docker.io/mcp/* is never signature-verified by the
    gateway (`isDockerMCPImage` gates that), so the digest abox pins is its only
    integrity anchor. The check must say that — not the myth that an unsigned
    image fails to start, which it doesn't."""
    from abox.manifest import CustomServers, Manifest

    custom = CustomServers(servers={"mine": _custom()})
    manifest = Manifest(project="d", profile="dev", servers=["mine"])
    checks = {c.id: c for c in doctor.check_custom_servers(manifest, custom)}
    assert checks["servers.custom"].status is doctor.Status.warn
    assert "docker.io/mcp/*" in checks["servers.custom"].hint
    assert "fails to start" not in checks["servers.custom"].hint


def _spec_with(**volumes_by_name: list[str]) -> gateway.GatewaySpec:
    return gateway.GatewaySpec(
        profile="dev",
        container="abox-gw-dev",
        image="img",
        port=8811,
        network="abox-net",
        servers=(),
        tools=(),
        token="tok",
        custom_servers=tuple(
            (name, _custom(volumes=vols)) for name, vols in volumes_by_name.items()
        ),
    )


def test_gateway_allow_lists_a_writable_host_volume() -> None:
    """The gateway refuses a host bind outside /tmp unless named. A custom server
    with a plain host volume must add it to the writable allow-list, or the
    server never starts (this is exactly what stopped Serena on a live run)."""
    opts = " ".join(_spec_with(serena=["/data/myproj:/workspace/myproj"]).run_options())
    assert "MCP_GATEWAY_DOCKER_BIND_ALLOW_WRITABLE_PATHS=/data/myproj" in opts
    assert "MCP_GATEWAY_DOCKER_BIND_ALLOWED_PATHS" not in opts  # nothing read-only


def test_gateway_read_only_volume_is_not_made_writable() -> None:
    """A `:ro` volume must land in the read-only allow-list, preserving the
    gateway's default that host binds are read-only unless explicitly trusted."""
    opts = " ".join(_spec_with(s=["/data/x:/workspace/x:ro"]).run_options())
    assert "MCP_GATEWAY_DOCKER_BIND_ALLOWED_PATHS=/data/x" in opts
    assert "WRITABLE" not in opts


def test_gateway_named_volume_needs_no_allow_list() -> None:
    opts = " ".join(_spec_with(s=["cache:/data"]).run_options())
    assert "BIND_ALLOW" not in opts


def test_adding_a_host_volume_changes_the_fingerprint() -> None:
    """The bind-allow paths are folded into the fingerprint, so adding a volume
    forces a gateway recreate — otherwise the new env never reaches the running
    container and the mount stays refused."""
    assert _spec_with(s=[]).fingerprint() != _spec_with(s=["/data/x:/workspace/x"]).fingerprint()


def test_no_custom_warning_when_none_declared(config: GlobalConfig) -> None:
    from abox.manifest import CustomServers, Manifest

    manifest = Manifest(project="d", profile="dev", servers=["duckduckgo"])
    assert doctor.check_custom_servers(manifest, CustomServers()) == []
