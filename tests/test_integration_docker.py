"""Tests that need a live Docker daemon.

Deselected by default (``-m "not docker"`` is implied by most CI); run them with
``uv run pytest -m docker``. They exercise the one thing unit tests cannot fake:
that a real gateway container, on a real user bridge, answers MCP over the exact
path an agent container will take — container DNS name, port, bearer token.
"""

from __future__ import annotations

import time

import pytest

from abox import catalog as catalog_mod
from abox import dockerx, gateway
from abox.manifest import GlobalConfig, ProfileConfig

pytestmark = pytest.mark.docker

TEST_PROFILE = "abox-pytest"
TEST_NETWORK = "abox-net-pytest"


@pytest.fixture(scope="function")
def live_config() -> GlobalConfig:
    ok, detail = dockerx.daemon_ok()
    if not ok:
        pytest.skip(f"no docker daemon: {detail}")
    return GlobalConfig(
        network=TEST_NETWORK,
        profiles={TEST_PROFILE: ProfileConfig(port=8977)},
    )


@pytest.fixture
def live_gateway(live_config: GlobalConfig):
    if not dockerx.image_present(live_config.gateway_image):
        result = dockerx.pull(live_config.gateway_image)
        if not result.ok:
            pytest.skip(f"cannot pull {live_config.gateway_image}: {result.stderr[:120]}")
    cat = catalog_mod.Catalog()
    try:
        status = gateway.up(TEST_PROFILE, live_config, cat, servers=[], pull_images=False)
        yield status
    finally:
        gateway.down(TEST_PROFILE)
        dockerx.docker("network", "rm", TEST_NETWORK)


def test_gateway_answers_mcp_over_the_bridge(live_config, live_gateway) -> None:
    assert live_gateway.running
    assert live_gateway.healthy
    assert "Gateway" in live_gateway.detail


def test_gateway_publishes_nothing_to_the_host(live_config, live_gateway) -> None:
    state = dockerx.container_state(live_gateway.container)
    assert state.published_ports == []


def test_probe_is_rejected_without_the_token(live_config, live_gateway) -> None:
    """The bearer token is the only thing gating the endpoint from everything
    else on the bridge, so prove an empty token actually fails."""
    spec = gateway.build_spec(TEST_PROFILE, live_config, servers=[])
    anonymous = type(spec)(
        profile=spec.profile,
        container=spec.container,
        image=spec.image,
        port=spec.port,
        network=spec.network,
        servers=spec.servers,
        tools=spec.tools,
        token="not-the-real-token",
    )
    assert not gateway.probe(anonymous).ok


def test_gateway_is_reconciled_not_duplicated(live_config, live_gateway) -> None:
    cat = catalog_mod.Catalog()
    again = gateway.up(TEST_PROFILE, live_config, cat, servers=[], pull_images=False)
    assert again.healthy
    names = dockerx.list_managed(role="gateway")
    assert names.count(live_gateway.container) == 1


def test_down_removes_the_container(live_config, live_gateway) -> None:
    assert gateway.down(TEST_PROFILE) is True
    assert not dockerx.container_state(live_gateway.container).exists


# -- remote MCP servers ----------------------------------------------------


@pytest.fixture
def live_remote_gateway(live_config: GlobalConfig):
    """A gateway fronting a real internet-hosted MCP server.

    Uses Context7's public endpoint: no image to pull, no credential, and it
    exercises the exact path a hosted connector takes — generated catalog,
    mounted into the gateway, reached only by the gateway.
    """
    from abox.manifest import RemoteServer

    if not dockerx.image_present(live_config.gateway_image):
        pytest.skip("gateway image not present")
    remotes = {"ctx7": RemoteServer(url="https://mcp.context7.com/mcp")}
    cat = catalog_mod.Catalog()
    try:
        status = gateway.up(
            TEST_PROFILE,
            live_config,
            cat,
            servers=[],
            remote_servers=remotes,
            pull_images=False,
        )
        yield status, remotes
    finally:
        gateway.down(TEST_PROFILE)
        dockerx.docker("network", "rm", TEST_NETWORK)


def test_remote_server_is_reachable_through_the_gateway(live_config, live_remote_gateway) -> None:
    status, remotes = live_remote_gateway
    assert status.healthy
    spec = gateway.build_spec(TEST_PROFILE, live_config, servers=[], remote_servers=remotes)
    probe = gateway.probe(spec, want_tools=True, timeout=120)
    assert probe.ok
    assert probe.tools, "the gateway exposed no tools from the remote server"


def test_remote_server_adds_no_published_port(live_config, live_remote_gateway) -> None:
    status, _ = live_remote_gateway
    assert dockerx.container_state(status.container).published_ports == []


# -- the agent container ---------------------------------------------------
#
# These build a real image and run a real container. They are the only place
# the firewall, the mask overlays, and the no-root property can actually be
# observed rather than inferred from a rendered file.


@pytest.fixture
def built_agent(live_config: GlobalConfig, tmp_path):
    """A built agent image plus a live gateway for it to point at."""
    from abox import render, runner
    from abox.manifest import Manifest, MountsConfig

    workspace = tmp_path / "agent-ws"
    workspace.mkdir()
    (workspace / ".env").write_text("SECRET=hunter2\n")
    (workspace / "keep.txt").write_text("visible\n")

    manifest = Manifest(
        project="pytest",
        profile=TEST_PROFILE,
        toolchains=[],
        mounts=MountsConfig(mask=[".env"]),
        egress=["example.com"],
    )
    cat = catalog_mod.Catalog()
    status = gateway.up(TEST_PROFILE, live_config, cat, servers=[], pull_images=False)
    spec = gateway.build_spec(TEST_PROFILE, live_config, servers=[])
    render.write(render.render(manifest, live_config, workspace, spec))

    result = runner.build(manifest, workspace)
    if not result.ok:
        gateway.down(TEST_PROFILE)
        pytest.skip(f"agent image build failed: {(result.stderr or result.stdout)[-300:]}")

    provisioned = runner.up(manifest, workspace, run_id="itest")
    try:
        yield manifest, workspace, provisioned, status
    finally:
        dockerx.remove(provisioned.container_name)
        gateway.down(TEST_PROFILE)
        dockerx.docker("network", "rm", TEST_NETWORK)


def _exec(container: str, *argv: str, user: str = "vscode"):
    return dockerx.docker("exec", "-u", user, container, *argv, timeout=90)


def test_agent_has_claude_and_no_npm(built_agent) -> None:
    _manifest, _ws, provisioned, _status = built_agent
    which = _exec(provisioned.container_name, "which", "claude")
    assert which.ok and "/usr/local/bin/claude" in which.stdout
    # No toolchain was requested, so nothing should have dragged Node in.
    assert not _exec(provisioned.container_name, "which", "npm").ok


def test_agent_cannot_become_root(built_agent) -> None:
    _manifest, _ws, provisioned, _status = built_agent
    whoami = _exec(provisioned.container_name, "id", "-un")
    assert whoami.stdout.strip() == "vscode"
    # sudo is either absent or stripped of its setuid bit; either way it fails.
    assert not _exec(provisioned.container_name, "sudo", "-n", "id", "-u").ok


def test_agent_cannot_reach_the_docker_socket(built_agent) -> None:
    _manifest, _ws, provisioned, _status = built_agent
    assert not _exec(provisioned.container_name, "test", "-S", "/var/run/docker.sock").ok


def test_masked_file_is_empty_inside_the_container(built_agent) -> None:
    _manifest, workspace, provisioned, _status = built_agent
    assert "hunter2" in (workspace / ".env").read_text()  # still there on the host
    inside = _exec(provisioned.container_name, "cat", "/workspace/.env")
    assert inside.ok
    assert inside.stdout.strip() == ""
    # The rest of the workspace is untouched.
    assert "visible" in _exec(provisioned.container_name, "cat", "/workspace/keep.txt").stdout


def test_firewall_marker_proves_the_rules_are_live(built_agent) -> None:
    from abox import runner

    _manifest, _workspace, provisioned, _status = built_agent
    check = runner.verify_firewall_live(provisioned.container_name, required=True)
    assert check.ok


def test_the_agent_cannot_edit_its_own_audit_trail(built_agent) -> None:
    """Docker Desktop does not enforce uid or mode on a bind mount, so the log
    dir is container-internal and root-owned. If the agent could truncate
    dns.log it would control the egress review queue."""
    _manifest, _workspace, provisioned, _status = built_agent
    c = provisioned.container_name
    assert not _exec(c, "touch", "/var/log/abox/probe").ok
    assert not _exec(c, "sh", "-c", ": > /var/log/abox/dns.log").ok
    assert not _exec(c, "sh", "-c", "echo forged > /var/log/abox/firewall-ok").ok
    owner = _exec(c, "stat", "-c", "%A %U", "/var/log/abox", user="root")
    assert owner.stdout.strip() == "drwxr-xr-x root"


def test_dns_resolution_is_scoped_to_the_allowlist(built_agent) -> None:
    """Arbitrary resolution is a covert channel that survives default-deny
    egress; the refused lookup must still be logged."""
    _manifest, _workspace, provisioned, _status = built_agent
    c = provisioned.container_name
    assert _exec(c, "getent", "hosts", "example.com").ok  # allowlisted in the fixture
    assert not _exec(c, "getent", "hosts", "exfil.attacker.invalid").ok
    log = _exec(c, "cat", "/var/log/abox/dns.log", user="root")
    assert "attacker.invalid" in log.stdout


def test_default_deny_egress(built_agent) -> None:
    """A domain nobody allowlisted must not be reachable."""
    _manifest, _ws, provisioned, _status = built_agent
    blocked = _exec(
        provisioned.container_name,
        "curl", "-sS", "--max-time", "8", "-o", "/dev/null", "https://pypi.org",
    )
    assert not blocked.ok


def test_the_gateway_is_reachable_from_the_agent(built_agent) -> None:
    """The one hole in the firewall: the profile gateway."""
    _manifest, _ws, provisioned, status = built_agent
    probe = _exec(
        provisioned.container_name,
        "bash", "-c",
        f"curl -sS --max-time 10 -o /dev/null -w '%{{http_code}}' {status.url}",
    )
    # 401 is the right answer: reachable, and refusing an unauthenticated caller.
    assert probe.stdout.strip() in ("401", "400", "405", "200")


def test_dns_lookups_are_harvested_at_teardown(built_agent) -> None:
    """The log dir is not shared, so it reaches the host through the socket."""
    from abox import paths, runner, telemetry

    _manifest, workspace, provisioned, _status = built_agent
    _exec(provisioned.container_name, "getent", "hosts", "telemetry.example.invalid")
    assert "dns.log" in runner.harvest_logs(provisioned)
    log = paths.current_run_dir(workspace) / "dns.log"
    assert log.is_file()
    names = {q.name for q in telemetry.parse_dns_log(log.read_text(errors="replace"))}
    assert any("example" in n for n in names)


def test_sudo_is_absent_from_the_image(built_agent) -> None:
    """Removed, not defanged: a present-but-neutered setuid binary is one
    config mistake away from working again, and abox reaches root through the
    Docker socket instead."""
    _manifest, _workspace, provisioned, _status = built_agent
    c = provisioned.container_name
    assert not _exec(c, "sh", "-c", "command -v sudo").ok
    assert not _exec(c, "sh", "-c", "command -v sudoedit || command -v visudo").ok
    assert not _exec(c, "test", "-e", "/etc/sudoers").ok
    # dpkg must not believe it is installed either, or a later apt-get install
    # of something depending on it could put it back.
    assert not _exec(c, "sh", "-c", 'dpkg -l sudo | grep -q "^ii"', user="root").ok
    # No suid sudo survives under another name.
    suid = _exec(c, "sh", "-c", "find / -xdev -perm -4000 -type f", user="root")
    assert "sudo" not in suid.stdout
    # And root has no password, so su is not an alternative route.
    shadow = _exec(c, "sh", "-c", "grep '^root:' /etc/shadow | cut -d: -f2", user="root")
    assert shadow.stdout.strip() in ("*", "!", "!*")


# -- SNI egress proxy ------------------------------------------------------


@pytest.fixture
def sni_agent(live_config: GlobalConfig, tmp_path):
    """An agent behind the SNI proxy, with one domain allowed."""
    from abox import proxy, render, runner
    from abox.manifest import Manifest, MountsConfig

    live_config.egress_proxy.enabled = True
    workspace = tmp_path / "sni-ws"
    workspace.mkdir()
    manifest = Manifest(
        project="snitest",
        profile=TEST_PROFILE,
        toolchains=[],
        mounts=MountsConfig(),
        egress=["example.com"],
    )
    status = gateway.up(TEST_PROFILE, live_config, catalog_mod.Catalog(), servers=[],
                        pull_images=False)
    spec = gateway.build_spec(TEST_PROFILE, live_config, servers=[])
    render.write(render.render(manifest, live_config, workspace, spec))

    if not dockerx.image_present(live_config.egress_proxy.image) and not dockerx.pull(
        live_config.egress_proxy.image
    ).ok:
        gateway.down(TEST_PROFILE)
        pytest.skip("cannot pull the proxy image")
    proxy.up(manifest, live_config, workspace)

    result = runner.build(manifest, workspace)
    if not result.ok:
        proxy.down(manifest.project)
        gateway.down(TEST_PROFILE)
        pytest.skip(f"agent build failed: {(result.stderr or result.stdout)[-200:]}")
    provisioned = runner.up(manifest, workspace, run_id="sni")
    try:
        yield manifest, workspace, provisioned, status
    finally:
        dockerx.remove(provisioned.container_name)
        proxy.down(manifest.project)
        gateway.down(TEST_PROFILE)
        dockerx.docker("network", "rm", TEST_NETWORK)


def test_the_sni_agent_firewall_is_actually_live(sni_agent) -> None:
    """Establish the proxy is in the path before trusting anything below it.

    The three tests that follow assert the proxy's behaviour, and every one of
    them would pass just as well if the firewall never applied: example.com
    would answer directly, and a forged SNI would be refused by example.com
    rather than by us. The fixture never checked, so on Linux — where sni.log
    came back empty while all three "passed" — there was no way to tell a
    working control from an absent one.
    """
    from abox import runner

    _m, _ws, provisioned, _s = sni_agent
    assert runner.verify_firewall_live(provisioned.container_name, required=True).ok

    nat = _exec(
        provisioned.container_name, "iptables", "-t", "nat", "-S", "OUTPUT", user="root"
    )
    assert nat.ok, nat.stderr
    assert "--dport 443" in nat.stdout, f"no 443 redirect installed:\n{nat.stdout}"


def test_the_allowed_connection_goes_through_the_proxy(sni_agent) -> None:
    """A 200 proves reachability, not that the proxy was involved.

    Only the proxy's own log proves the traffic took the intended path, which is
    the difference between "egress works" and "egress is being filtered".
    """
    from abox import proxy

    _m, _ws, provisioned, _s = sni_agent
    r = _exec(provisioned.container_name, "curl", "-sS", "-o", "/dev/null",
              "-w", "%{http_code}", "-m", "25", "https://example.com")
    assert r.stdout.strip() == "200", r.stderr

    deadline = time.monotonic() + 20
    seen = ""
    while time.monotonic() < deadline:
        got = dockerx.docker(
            "exec", proxy.proxy_container("snitest"), "cat", "/var/log/nginx/sni.log",
            timeout=30,
        )
        seen = got.stdout or ""
        if "example.com" in seen:
            return
        time.sleep(0.5)
    raise AssertionError(
        f"the proxy never logged the allowed connection — sni.log:\n{seen or '(empty)'}"
    )


def test_allowed_domain_passes_the_proxy(sni_agent) -> None:
    _m, _ws, provisioned, _s = sni_agent
    r = _exec(provisioned.container_name, "curl", "-sS", "-o", "/dev/null",
              "-w", "%{http_code}", "-m", "25", "https://example.com")
    assert r.stdout.strip() == "200"


def _await_denied_sni(project: str, name: str, timeout: float = 20.0) -> bool:
    """Poll for a refused SNI rather than assuming it is logged by the time the
    client exits.

    nginx writes the stream access_log on connection *close*, so the entry can
    trail curl returning. macOS never lost that race because the exec round-trip
    through Docker Desktop is slow enough to hide it; on Linux it is not. The
    ordering was always unguaranteed — asserting it once was the bug.
    """
    from abox import proxy

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(d["sni"] == name for d in proxy.denied_names(project)):
            return True
        time.sleep(0.5)
    return False


def _sni_log_diagnostics(project: str) -> str:
    """What the proxy actually has, for when the polling above comes up empty.

    A bare "never logged" says the entry is missing without saying whether the
    file is empty, absent, or full of lines in a shape denied_names does not
    recognise — three different bugs.
    """
    from abox import proxy

    container = proxy.proxy_container(project)
    state = dockerx.container_state(container)
    parts = [f"container={container} running={state.running}"]
    for cmd in (
        ["ls", "-la", "/var/log/nginx"],
        ["cat", "/var/log/nginx/sni.log"],
        ["cat", "/var/log/nginx/error.log"],
    ):
        r = dockerx.docker("exec", container, *cmd, timeout=30)
        body = (r.stdout or r.stderr).strip() or "(empty)"
        parts.append(f"$ {' '.join(cmd)}\n{body[:1200]}")
    parts.append(f"docker logs:\n{dockerx.logs(container, tail=20)[-800:]}")
    return "\n\n".join(parts)


def test_domain_fronting_is_refused(sni_agent) -> None:
    """The finding this whole component exists for: an allowed *address* with a
    forged server name must not get through. An ipset cannot tell these apart."""
    _m, _ws, provisioned, _s = sni_agent
    c = provisioned.container_name
    forged = _exec(
        c, "bash", "-lc",
        'IP=$(getent hosts example.com | head -1 | cut -d" " -f1); '
        'curl -sS -o /dev/null -m 15 --resolve pypi.org:443:$IP https://pypi.org',
    )
    assert not forged.ok
    # And the attempt is recorded with the name that was attempted.
    if not _await_denied_sni("snitest", "pypi.org"):
        raise AssertionError(
            "the fronting attempt was refused but never reached the review "
            f"queue:\n\n{_sni_log_diagnostics('snitest')}"
        )


def test_no_sni_connection_is_refused(sni_agent) -> None:
    """A negative test cannot tell "the proxy refused it" from "the proxy was
    never running", so establish the proxy is alive before believing the refusal.
    On Linux it genuinely was not running until the artifact modes were fixed,
    and this test passed throughout.
    """
    from abox import proxy

    assert dockerx.container_state(proxy.proxy_container("snitest")).running

    _m, _ws, provisioned, _s = sni_agent
    r = _exec(
        provisioned.container_name, "bash", "-lc",
        'IP=$(getent hosts example.com | head -1 | cut -d" " -f1); '
        'curl -skS -o /dev/null -m 15 -H "Host: pypi.org" https://$IP',
    )
    assert not r.ok


def test_the_proxy_publishes_nothing(sni_agent) -> None:
    from abox import proxy

    state = dockerx.container_state(proxy.proxy_container("snitest"))
    assert state.running
    assert state.published_ports == []
