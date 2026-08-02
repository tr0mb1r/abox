"""Schema behaviour — the manifest is also the doctor's specification."""

from __future__ import annotations

from pathlib import Path

import pytest

from abox.errors import ConfigError
from abox.manifest import (
    DEFAULT_GATEWAY_IMAGE,
    GATEWAY_IMAGE_TAG,
    CustomServer,
    CustomServers,
    GlobalConfig,
    Manifest,
    MountsConfig,
    PermissionMode,
    ProfileConfig,
    SecretMapping,
    SecretsConfig,
    SecretSource,
    effective_allowlist,
    merged_egress,
    merged_masks,
)


def test_manifest_round_trips(workspace: Path, manifest: Manifest) -> None:
    manifest.write(workspace)
    assert Manifest.load(workspace) == manifest


def test_manifest_rejects_unknown_fields() -> None:
    with pytest.raises(ConfigError, match="extra_field"):
        Manifest.parse_yaml("project: a\nprofile: b\nextra_field: 1\n")


def test_manifest_rejects_future_version() -> None:
    with pytest.raises(ConfigError, match="unsupported manifest version"):
        Manifest.parse_yaml("version: 2\nproject: a\nprofile: b\n")


@pytest.mark.parametrize(
    "egress",
    [
        "https://github.com",  # scheme
        "github.com/org",  # path
        "github.com:443",  # port
        "*.github.com",  # wildcard
        "not a host",
    ],
)
def test_egress_rejects_non_hostnames(egress: str) -> None:
    with pytest.raises(ConfigError):
        Manifest.parse_yaml(f"project: a\nprofile: b\negress: ['{egress}']\n")


def test_egress_normalises_and_dedupes() -> None:
    m = Manifest.parse_yaml("project: a\nprofile: b\negress: [GitHub.com, github.com]\n")
    assert m.egress == ["github.com"]


def test_wildcard_egress_explains_why() -> None:
    """A wildcard silently covering nothing would be the worst outcome."""
    with pytest.raises(ConfigError, match="ipset"):
        Manifest.parse_yaml("project: a\nprofile: b\negress: ['*.example.com']\n")


def test_unknown_toolchain_lists_the_known_ones() -> None:
    with pytest.raises(ConfigError, match="python"):
        Manifest.parse_yaml("project: a\nprofile: b\ntoolchains: [cobol]\n")


def test_tools_must_reference_declared_servers() -> None:
    with pytest.raises(ConfigError, match="undeclared server"):
        Manifest.parse_yaml(
            "project: a\nprofile: b\nservers: [github]\ntools:\n  supabase: [x]\n"
        )


def test_mask_globs_cannot_escape_the_workspace() -> None:
    with pytest.raises(ConfigError, match="escape"):
        Manifest.parse_yaml("project: a\nprofile: b\nmounts:\n  mask: ['../../etc']\n")


def test_mask_globs_must_be_relative() -> None:
    with pytest.raises(ConfigError, match="workspace-relative"):
        Manifest.parse_yaml("project: a\nprofile: b\nmounts:\n  mask: ['/etc/passwd']\n")


def test_context_mounts_get_unique_targets() -> None:
    mounts = MountsConfig(context=["~/notes/dev", "/srv/dev"])
    targets = [target for _host, target in mounts.context_mounts()]
    assert targets == ["/context/dev", "/context/dev-2"]


def test_bypass_permissions_flags_the_boundary_gate() -> None:
    m = Manifest.parse_yaml(
        "project: a\nprofile: b\nrun:\n  permission_mode: bypassPermissions\n"
    )
    assert m.run.requires_boundary_gate is True
    assert m.run.permission_mode is PermissionMode.bypass_permissions


def test_default_permission_mode_does_not_demand_the_gate(manifest: Manifest) -> None:
    assert manifest.run.requires_boundary_gate is False


# -- global config --------------------------------------------------------


def test_profiles_cannot_share_a_port() -> None:
    with pytest.raises(ValueError, match="both claim port"):
        GlobalConfig(profiles={"a": ProfileConfig(port=8811), "b": ProfileConfig(port=8811)})


def test_unknown_profile_lists_the_known_ones(config: GlobalConfig) -> None:
    with pytest.raises(ConfigError, match="unknown profile") as exc:
        config.profile("nope")
    assert "dev, secops" in (exc.value.hint or "")


def test_global_config_saves_private(config: GlobalConfig) -> None:
    path = config.save()
    assert path.stat().st_mode & 0o077 == 0
    assert GlobalConfig.load() == config


def test_gateway_image_pinned_detection() -> None:
    # The shipped default is pinned: the gateway holds the Docker socket, so it
    # gets the same treatment as every MCP server image.
    assert GlobalConfig().gateway_image_pinned
    assert GlobalConfig().gateway_image == DEFAULT_GATEWAY_IMAGE
    assert DEFAULT_GATEWAY_IMAGE.startswith(GATEWAY_IMAGE_TAG.split(":")[0] + "@sha256:")
    pinned = GlobalConfig(gateway_image="docker/mcp-gateway@sha256:" + "a" * 64)
    assert pinned.gateway_image_pinned
    assert not GlobalConfig(gateway_image="docker/mcp-gateway:v2").gateway_image_pinned


def test_server_network_must_reference_a_declared_server() -> None:
    with pytest.raises(ConfigError, match="undeclared server"):
        Manifest.parse_yaml(
            "project: a\nprofile: b\nservers: [git]\nserver_network:\n  brave: none\n"
        )


def test_server_network_is_refused_for_remote_servers() -> None:
    """The gateway dials these in-process; there is no container to place."""
    with pytest.raises(ConfigError, match="does not apply to remote"):
        Manifest.parse_yaml(
            "project: a\nprofile: b\n"
            "remote_servers:\n  ctx:\n    url: https://mcp.context7.com/mcp\n"
            "server_network:\n  ctx: none\n"
        )


def test_merged_masks_keeps_order_and_dedupes(manifest: Manifest, config: GlobalConfig) -> None:
    config.defaults.mask = [".env*", ".git/hooks"]
    manifest.mounts.mask = ["secrets/", ".env*"]
    assert merged_masks(manifest, config) == [".env*", ".git/hooks", "secrets/"]


def test_merged_egress_injects_the_mandatory_entries(
    manifest: Manifest, config: GlobalConfig
) -> None:
    assert "api.anthropic.com" in merged_egress(manifest, config)


def test_connectors_widen_the_allowlist_everywhere_not_just_at_render(
    manifest: Manifest, config: GlobalConfig
) -> None:
    """`run.connectors` is an egress decision. Only `render` used to add the
    connector host, so the enforced allowlist was one domain wider than every
    path that reports it — and the review queue flagged an allowed host on
    every run."""
    assert "mcp-proxy.anthropic.com" not in merged_egress(manifest, config)
    assert "mcp-proxy.anthropic.com" not in effective_allowlist(manifest, config)
    manifest.run.connectors = True
    assert "mcp-proxy.anthropic.com" in merged_egress(manifest, config)
    assert "mcp-proxy.anthropic.com" in effective_allowlist(manifest, config)


# -- custom servers -------------------------------------------------------


def test_an_empty_tools_filter_is_refused_not_read_as_everything() -> None:
    """`tools: {github: []}` reads as "expose nothing" and meant "expose
    everything": the flattened filter is empty, so no `--tools=` argument is
    emitted and the gateway publishes the server's whole surface — while doctor
    still advises narrowing with `tools:`."""
    with pytest.raises(ConfigError, match="empty tools filter"):
        Manifest.parse_yaml(
            "project: a\nprofile: b\nservers: [github]\ntools:\n  github: []\n"
        )


def test_a_real_tools_filter_still_narrows() -> None:
    """The positive path: a named filter reaches the gateway argument that
    enforces it, so the rule above rejects the ambiguous spelling only."""
    m = Manifest.parse_yaml(
        "project: a\nprofile: b\nservers: [github]\ntools:\n  github: [list_issues]\n"
    )
    assert m.tools == {"github": ["list_issues"]}


def test_custom_server_tools_may_not_be_empty() -> None:
    """Same trap in custom-servers.yaml: `all_tools` treated [] as ['*'], so the
    catalog entry carried no `tools` key and the server was not narrowed."""
    with pytest.raises(ValueError, match="tools must not be empty"):
        CustomServer(image="ghcr.io/me/x@sha256:" + "a" * 64, tools=[])


def test_custom_server_tools_narrowing_reaches_the_catalog_entry() -> None:
    server = CustomServer(image="ghcr.io/me/x@sha256:" + "a" * 64, tools=["only_this"])
    assert not server.all_tools
    assert server.catalog_entry("x")["tools"] == [{"name": "only_this"}]
    wide = CustomServer(image="ghcr.io/me/x@sha256:" + "a" * 64)
    assert wide.all_tools
    assert "tools" not in wide.catalog_entry("x")


def test_custom_server_requires_a_digest() -> None:
    with pytest.raises(ValueError, match="digest-pinned"):
        CustomServer(image="ghcr.io/oraios/serena:latest")


def test_custom_server_pin_false_allows_a_local_tag() -> None:
    """A local image you built and never pushed has no registry digest; `pin:
    false` is the explicit opt-out that lets abox run it on trust."""
    server = CustomServer(image="serena:local", pin=False)
    assert server.image == "serena:local"
    assert server.pin is False


def test_custom_server_pin_false_still_accepts_a_digest() -> None:
    server = CustomServer(image="ghcr.io/me/x@sha256:" + "a" * 64, pin=False)
    assert server.pin is False


def test_custom_servers_accepts_the_bare_mapping_shape(tmp_path: Path) -> None:
    from abox import paths

    paths.config_home().mkdir(parents=True, exist_ok=True)
    paths.custom_servers_path().write_text(
        f"serena:\n  image: ghcr.io/oraios/serena@sha256:{'b' * 64}\n  tools: ['*']\n"
    )
    loaded = CustomServers.load()
    assert "serena" in loaded
    assert loaded.get("serena").all_tools is True  # type: ignore[union-attr]


# -- secrets mappings -----------------------------------------------------


def test_secret_mapping_infers_its_source() -> None:
    assert SecretMapping(secret="a", op="op://v/i/f").kind is SecretSource.op
    assert SecretMapping(secret="a", file="~/x").kind is SecretSource.file
    assert SecretMapping(secret="a", env="TOKEN").kind is SecretSource.env
    assert SecretMapping(secret="a", source=SecretSource.docker).kind is SecretSource.docker


def test_secret_mapping_rejects_two_sources() -> None:
    with pytest.raises(ValueError, match="more than one source"):
        SecretMapping(secret="a", op="op://v/i/f", env="TOKEN")


def test_secret_mapping_requires_a_source() -> None:
    with pytest.raises(ValueError, match="no source"):
        SecretMapping(secret="a")


def test_docker_and_prompt_sources_are_not_readable() -> None:
    assert SecretMapping(secret="a", source=SecretSource.docker).readable is False
    assert SecretMapping(secret="a", source=SecretSource.prompt).readable is False
    assert SecretMapping(secret="a", env="TOKEN").readable is True


def test_op_is_not_required(tmp_path: Path) -> None:
    """The whole point of the softening: a config with no op reference is valid."""
    cfg = SecretsConfig(
        mappings=[
            SecretMapping(secret="a", file="/tmp/x"),
            SecretMapping(secret="b", source=SecretSource.docker),
        ]
    )
    assert cfg.needs_op() is False


def test_op_reference_must_be_complete() -> None:
    with pytest.raises(ValueError, match="incomplete op reference"):
        SecretMapping(secret="a", op="op://vault")


def test_duplicate_secret_targets_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate secret target"):
        SecretsConfig(
            mappings=[
                SecretMapping(secret="a", env="X"),
                SecretMapping(secret="a", env="Y"),
            ]
        )


def test_server_names_may_be_mixed_case() -> None:
    """`SQLite` is a real key in the Docker MCP catalog — and it sorts first, so
    rejecting it made the very first entry in the picker unselectable."""
    m = Manifest.parse_yaml("project: a\nprofile: b\nservers: [SQLite, duckduckgo]\n")
    assert m.servers == ["SQLite", "duckduckgo"]


def test_remote_server_names_may_be_mixed_case() -> None:
    m = Manifest.parse_yaml(
        "project: a\nprofile: b\n"
        "remote_servers:\n  Context7:\n    url: https://mcp.context7.com/mcp\n"
    )
    assert "Context7" in m.remote_servers


@pytest.mark.parametrize("bad", ["two words", "a,b", "a/b", "-leading", "a;rm -rf /"])
def test_server_names_still_reject_unsafe_shapes(bad: str) -> None:
    """The name is concatenated into `--servers=a,b,c`, so anything that could
    split or escape that argument stays rejected."""
    with pytest.raises(ConfigError):
        Manifest.parse_yaml(f"project: a\nprofile: b\nservers: ['{bad}']\n")


def test_project_and_profile_stay_lowercase() -> None:
    """These become Docker image, container, and volume names."""
    with pytest.raises(ConfigError, match="lowercase"):
        Manifest.parse_yaml("project: MyProject\nprofile: b\n")
    with pytest.raises(ConfigError, match="lowercase"):
        Manifest.parse_yaml("project: a\nprofile: Trading\n")


def test_a_domain_cannot_be_both_allowed_and_ignored() -> None:
    with pytest.raises(ConfigError, match="not both"):
        Manifest.parse_yaml(
            "project: a\nprofile: b\negress: [example.com]\negress_ignored: [example.com]\n"
        )


def test_a_mandatory_domain_is_dropped_from_ignored_on_load() -> None:
    """`abox egress ignore claude.ai` recorded a denial and said "still blocked"
    for a host `merged_egress` unions in unconditionally: the firewall kept
    routing to it and the review queue stopped mentioning it.

    Dropped on load rather than rejected. Refusing the *file* bricks a manifest
    an older abox wrote — every command fails, including `abox egress unignore`,
    which is the documented repair. The entry is a no-op either way, so removing
    it keeps the invariant without stranding anyone; the refusal lives in
    `abox egress ignore`, where the decision is actually made.
    """
    m = Manifest.parse_yaml("project: a\nprofile: b\negress_ignored: [claude.ai, evil.example]\n")
    assert m.egress_ignored == ["evil.example"]


def test_a_connector_domain_is_dropped_too_when_connectors_are_on() -> None:
    """merged_egress unions CONNECTOR_EGRESS on exactly the same unconditional
    terms, so ignoring one was the same contradiction one line lower."""
    on = Manifest.parse_yaml(
        "project: a\nprofile: b\nrun:\n  connectors: true\n"
        "egress_ignored: [mcp-proxy.anthropic.com]\n"
    )
    assert on.egress_ignored == []
    # With connectors off it is genuinely not allowed, so ignoring it is a real
    # decision and must survive.
    off = Manifest.parse_yaml(
        "project: a\nprofile: b\negress_ignored: [mcp-proxy.anthropic.com]\n"
    )
    assert off.egress_ignored == ["mcp-proxy.anthropic.com"]


def test_ignoring_an_ordinary_domain_still_works(config: GlobalConfig) -> None:
    """The positive path through the same rule — a check that rejected every
    ignore would only move the lie somewhere else."""
    m = Manifest.parse_yaml("project: a\nprofile: b\negress_ignored: [evil.example]\n")
    assert m.egress_ignored == ["evil.example"]
    assert "evil.example" not in merged_egress(m, config)


def test_ignored_domains_are_validated_like_egress() -> None:
    with pytest.raises(ConfigError):
        Manifest.parse_yaml("project: a\nprofile: b\negress_ignored: ['https://x.com']\n")


def test_one_bad_custom_server_does_not_break_every_project(tmp_path, monkeypatch) -> None:
    """custom-servers.yaml is global and loaded by nearly every command, so
    raising on a single invalid entry takes down projects that never mention it.
    The entry is dropped and named instead — the same treatment a catalog file
    that will not parse already gets."""
    from abox import paths as paths_mod
    from abox.manifest import CustomServers

    path = paths_mod.custom_servers_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "good:\n  image: r/i@sha256:" + "a" * 64 + "\n"
        "stale:\n  image: r/j@sha256:" + "b" * 64 + "\n  tools: []\n",
        encoding="utf-8",
    )

    custom = CustomServers.load()  # must not raise
    assert "good" in custom.servers
    assert "stale" not in custom.servers
    assert "stale" in custom.rejected
    assert "tools" in custom.rejected["stale"]
