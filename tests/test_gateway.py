"""Gateway spec, profile registry, probing, and token hygiene."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from abox import gateway
from abox.manifest import GlobalConfig

#: What a misconfigured gateway would bind to; asserted against, never used.
ALL_INTERFACES = "0.0.0." + "0"


def test_spec_publishes_nothing(config: GlobalConfig) -> None:
    spec = gateway.build_spec("dev", config, servers=["duckduckgo"])
    opts = spec.run_options()
    assert "-p" not in opts
    assert not any(o.startswith("--publish") for o in opts)


def test_spec_mounts_the_socket_and_sets_the_token(config: GlobalConfig) -> None:
    spec = gateway.build_spec("dev", config, servers=[])
    opts = " ".join(spec.run_options())
    assert "/var/run/docker.sock:/var/run/docker.sock" in opts
    assert f"MCP_GATEWAY_AUTH_TOKEN={spec.token}" in opts


def test_gateway_args_carry_the_hardening_flags(config: GlobalConfig) -> None:
    spec = gateway.build_spec("dev", config, servers=["a", "b"], tools=["x"])
    args = spec.gateway_args()
    assert "--verify-signatures" in args
    assert "--log-calls" in args
    assert "--block-secrets" in args
    assert "--transport=streaming" in args
    assert "--port=8811" in args
    # Without this the gateway binds loopback inside its own container and no
    # sibling container can reach it.
    assert "--host=0.0.0.0" in args
    assert "--servers=a,b" in args
    assert "--tools=x" in args


def test_url_is_container_dns_not_localhost(config: GlobalConfig) -> None:
    spec = gateway.build_spec("dev", config, servers=[])
    assert spec.url == "http://abox-gw-dev:8811/mcp"


def test_token_is_stable_and_private(config: GlobalConfig) -> None:
    first = gateway.ensure_token("dev")
    assert gateway.ensure_token("dev") == first
    assert gateway.token_path("dev").stat().st_mode & 0o077 == 0


def test_tokens_differ_per_profile() -> None:
    assert gateway.ensure_token("dev") != gateway.ensure_token("secops")


def test_fingerprint_changes_with_the_server_set(config: GlobalConfig) -> None:
    a = gateway.build_spec("dev", config, servers=["x"]).fingerprint()
    b = gateway.build_spec("dev", config, servers=["x", "y"]).fingerprint()
    assert a != b


def test_fingerprint_ignores_the_token(config: GlobalConfig) -> None:
    """Re-minting a token should not force a container recreate on its own."""
    spec = gateway.build_spec("dev", config, servers=["x"])
    assert spec.token not in spec.fingerprint()


def test_mcp_config_is_bearer_authenticated(config: GlobalConfig) -> None:
    spec = gateway.build_spec("dev", config, servers=[])
    cfg = gateway.mcp_config(spec)
    entry = cfg["mcpServers"]["abox-gateway"]
    assert entry["type"] == "http"
    assert entry["url"] == spec.url
    assert entry["headers"]["Authorization"] == f"Bearer {spec.token}"
    assert len(cfg["mcpServers"]) == 1  # exactly one endpoint


# -- profile registry -----------------------------------------------------


def test_registry_unions_servers_across_projects(tmp_path: Path) -> None:
    reg = gateway.ProfileRegistry(profile="dev")
    reg.register(project_hash="a", workspace="/a", project="a", servers=["x"], tools={})
    reg.register(project_hash="b", workspace="/b", project="b", servers=["y"], tools={})
    assert reg.servers == ["x", "y"]


def test_registry_narrows_tools_only_when_every_project_narrows() -> None:
    reg = gateway.ProfileRegistry(profile="dev")
    reg.register(
        project_hash="a", workspace="/a", project="a", servers=["db"], tools={"db": ["read"]}
    )
    reg.register(
        project_hash="b", workspace="/b", project="b", servers=["db"], tools={"db": ["write"]}
    )
    assert reg.tools == ["read", "write"]

    # One project wants the whole server: narrowing would silently break it.
    reg.register(project_hash="c", workspace="/c", project="c", servers=["db"], tools={})
    assert reg.tools == []


def test_registry_round_trips(tmp_path: Path) -> None:
    reg = gateway.ProfileRegistry(profile="dev")
    reg.register(project_hash="a", workspace="/a", project="a", servers=["x"], tools={})
    reg.save()
    assert gateway.ProfileRegistry.load("dev").servers == ["x"]
    assert gateway.registry_path("dev").stat().st_mode & 0o077 == 0


def test_bind_and_unbind_project(workspace: Path) -> None:
    gateway.bind_project(
        "dev", workspace=workspace, project="demo", servers=["x"], tools={}
    )
    assert gateway.ProfileRegistry.load("dev").servers == ["x"]
    gateway.unbind_project("dev", workspace)
    assert gateway.ProfileRegistry.load("dev").servers == []


# -- probing --------------------------------------------------------------

_INIT_SSE = (
    'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":'
    '{"protocolVersion":"2025-06-18","serverInfo":{"name":"Docker AI MCP Gateway",'
    '"version":"2.0.1"}}}\n'
)
_TOOLS_SSE = (
    'event: message\ndata: {"jsonrpc":"2.0","id":2,"result":'
    '{"tools":[{"name":"search"},{"name":"fetch_content"}]}}\n'
)


def test_probe_reports_the_server_info(config: GlobalConfig, runner) -> None:
    runner.expect(r"docker run --rm --network", _INIT_SSE)
    spec = gateway.build_spec("dev", config, servers=[])
    result = gateway.probe(spec)
    assert result.ok
    assert result.detail == "Docker AI MCP Gateway 2.0.1"


def test_probe_collects_tools(config: GlobalConfig, runner) -> None:
    runner.expect(r"docker run --rm", _INIT_SSE + _TOOLS_SSE)
    spec = gateway.build_spec("dev", config, servers=[])
    result = gateway.probe(spec, want_tools=True)
    assert result.tools == ("search", "fetch_content")


def test_probe_fails_closed_on_a_401(config: GlobalConfig, runner) -> None:
    runner.expect(r"docker run --rm", "", returncode=1, stderr="401 Unauthorized")
    spec = gateway.build_spec("dev", config, servers=[])
    result = gateway.probe(spec)
    assert not result.ok
    assert "401" in result.detail


def test_probe_uses_the_gateway_image_so_nothing_extra_is_pulled(
    config: GlobalConfig, runner
) -> None:
    runner.expect(r"docker run --rm", _INIT_SSE)
    spec = gateway.build_spec("dev", config, servers=[])
    gateway.probe(spec)
    call = runner.find("docker run --rm")[0]
    assert config.gateway_image in call.argv
    assert "--entrypoint" in call.argv


# -- log hygiene ----------------------------------------------------------


def test_sanitize_redacts_the_token(config: GlobalConfig) -> None:
    token = gateway.ensure_token("dev")
    text = f"Use Bearer token: {token}\nauthorization: Bearer {token}"
    cleaned = gateway.sanitize_for_log(text, profile="dev")
    assert token not in cleaned
    assert "«gateway-token»" in cleaned


def test_sanitize_redacts_unknown_bearer_headers() -> None:
    cleaned = gateway.sanitize_for_log("Authorization: Bearer abc.def.ghi")
    assert "abc.def.ghi" not in cleaned


# -- image pre-pull -------------------------------------------------------


def test_ensure_server_images_pulls_missing_ones(
    config: GlobalConfig, runner, catalog_file
) -> None:
    from abox import catalog as catalog_mod

    runner.expect(r"docker image inspect", "", returncode=1)  # nothing present
    runner.expect(r"docker pull", "pulled")
    cat = catalog_mod.load(allow_oci_fallback=False)
    spec = gateway.build_spec("dev", config, servers=["duckduckgo"])
    pulled = gateway.ensure_server_images(spec, cat)
    assert any("duckduckgo" in image for image in pulled)


def test_ensure_server_images_explains_the_pull_never_trap(
    config: GlobalConfig, runner, catalog_file
) -> None:
    from abox import catalog as catalog_mod
    from abox.errors import GatewayError

    runner.expect(r"docker image inspect", "", returncode=1)
    runner.expect(r"docker pull", "", returncode=1, stderr="no space left on device")
    cat = catalog_mod.load(allow_oci_fallback=False)
    spec = gateway.build_spec("dev", config, servers=["duckduckgo"])
    with pytest.raises(GatewayError, match="could not pull") as exc:
        gateway.ensure_server_images(spec, cat)
    assert "pull never" in (exc.value.hint or "")


def test_status_reports_a_missing_container(config: GlobalConfig, runner) -> None:
    runner.expect(r"docker container inspect", "", returncode=1)
    status = gateway.status("dev", config)
    assert not status.exists
    assert status.detail == "not created"


def test_status_flags_published_ports(config: GlobalConfig, runner) -> None:
    inspected = {
        "State": {"Running": True, "Status": "running"},
        "Config": {"Image": "docker/mcp-gateway:v2", "Labels": {}},
        "NetworkSettings": {
            "Ports": {"8811/tcp": [{"HostIp": ALL_INTERFACES, "HostPort": "8811"}]}
        },
    }
    runner.expect(r"docker container inspect", json.dumps(inspected))
    runner.expect(r"docker run --rm", _INIT_SSE)
    status = gateway.status("dev", config)
    assert status.published_ports == (f"{ALL_INTERFACES}:8811->8811/tcp",)
