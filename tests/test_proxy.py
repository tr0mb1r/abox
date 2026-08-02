"""The SNI-aware egress proxy.

The property under test: with the proxy on, the allowlist is domain-level. An
ipset can only match addresses, so it cannot separate two domains sharing an IP
— which is not hypothetical, since pypi.org and files.pythonhosted.org share
four Fastly addresses.
"""

from __future__ import annotations

import pytest

from abox import doctor, gateway, proxy, render
from abox.errors import AboxError
from abox.manifest import GlobalConfig


@pytest.fixture
def proxied(config: GlobalConfig) -> GlobalConfig:
    config.egress_proxy.enabled = True
    return config


@pytest.fixture
def spec(config: GlobalConfig) -> gateway.GatewaySpec:
    return gateway.build_spec("dev", config, servers=[])


# -- the rendered nginx config ---------------------------------------------


def test_allowlist_becomes_an_sni_map(manifest, proxied, workspace, spec) -> None:
    conf = render.render(manifest, proxied, workspace, spec).artifacts[render.ARTIFACT_PROXY]
    assert "ssl_preread on;" in conf
    assert '"github.com" "github.com:443";' in conf
    assert '"api.anthropic.com" "api.anthropic.com:443";' in conf
    # An unlisted name goes to the deny sentinel: refused, and — unlike an
    # empty upstream — refused somewhere nginx still runs its log phase.
    from abox import proxy as proxy_mod

    assert f'default "{proxy_mod.DENY_SENTINEL}";' in conf
    assert 'default "";' not in conf


def test_the_proxy_does_not_terminate_tls(manifest, proxied, workspace, spec) -> None:
    """No CA to install in the agent, no certificate to trust, nothing inside
    the tunnel visible to abox — only the destination name."""
    conf = render.render(manifest, proxied, workspace, spec).artifacts[render.ARTIFACT_PROXY]
    assert "ssl_certificate" not in conf
    assert "ssl_preread on;" in conf


def test_denied_attempts_are_logged_with_their_sni(manifest, proxied, workspace, spec) -> None:
    conf = render.render(manifest, proxied, workspace, spec).artifacts[render.ARTIFACT_PROXY]
    assert "$ssl_preread_server_name" in conf.split("log_format")[1][:200]


def test_denied_names_recognises_the_sentinel(manifest, runner) -> None:
    """The parser has to match what the template now writes.

    Both forms are accepted: a log written before the sentinel landed still
    parses, so upgrading does not blank the queue.
    """
    from abox import proxy as proxy_mod

    runner.expect(
        r"docker exec .* cat .*sni\.log",
        f'2026-07-25T10:00:00+00:00 client=172.18.0.9 sni="pypi.org" '
        f'upstream="{proxy_mod.DENY_SENTINEL}" status=502 bytes=0\n'
        '2026-07-25T10:00:01+00:00 client=172.18.0.9 sni="old.example" '
        'upstream="-" status=502 bytes=0\n'
        '2026-07-25T10:00:02+00:00 client=172.18.0.9 sni="example.com" '
        'upstream="93.184.216.34:443" status=200 bytes=5120\n',
    )
    names = {d["sni"] for d in proxy_mod.denied_names("demo")}
    assert names == {"pypi.org", "old.example"}, names


# -- the firewall changes shape --------------------------------------------


def test_proxy_mode_replaces_address_allowlisting(manifest, proxied, workspace, spec) -> None:
    """The point: stop allowlisting addresses, because addresses are the thing
    that cannot be trusted to identify a domain."""
    script = render.render(manifest, proxied, workspace, spec).artifacts[render.ARTIFACT_FIREWALL]
    assert "--dport 443" in script and "DNAT" in script
    assert "match-set" not in script          # no ipset rule at all
    assert 'PROXY_HOST="abox-proxy-demo"' in script


def test_without_the_proxy_the_ipset_path_remains(manifest, config, workspace, spec) -> None:
    script = render.render(manifest, config, workspace, spec).artifacts[render.ARTIFACT_FIREWALL]
    assert "match-set" in script
    assert "DNAT" not in script


def test_the_firewall_refuses_when_the_proxy_is_unreachable(
    manifest, proxied, workspace, spec
) -> None:
    """With the proxy configured but absent there is no egress path at all, so
    coming up 'successfully' would be a lie."""
    script = render.render(manifest, proxied, workspace, spec).artifacts[render.ARTIFACT_FIREWALL]
    assert "is not resolvable — refusing to run" in script


# -- the container ---------------------------------------------------------


def test_proxy_publishes_nothing_and_drops_capabilities(manifest, proxied, workspace) -> None:
    spec = proxy.build_spec(manifest, proxied, workspace)
    opts = spec.run_options()
    assert "-p" not in opts
    assert "--cap-drop" in opts and "ALL" in opts
    assert "--read-only" in opts
    # Runs *as* nginx: with every capability dropped the master cannot setgid,
    # so letting nginx drop privileges itself kills the worker on startup.
    assert f"{proxy.NGINX_UID}:{proxy.NGINX_GID}" in opts
    assert f"{spec.conf}:{proxy.CONTAINER_CONF}:ro" in opts


def test_fingerprint_covers_how_it_is_run(manifest, proxied, workspace, spec) -> None:
    """A change in how abox runs the proxy must recreate it, or an upgrade
    silently keeps the old container."""
    render.write(render.render(manifest, proxied, workspace, spec))
    before = proxy.build_spec(manifest, proxied, workspace).fingerprint()
    proxied.egress_proxy.port = 9443
    assert proxy.build_spec(manifest, proxied, workspace).fingerprint() != before


def test_spec_egress_equals_the_rendered_map(manifest, proxied, workspace, spec) -> None:
    """What abox reports must be what nginx enforces.

    `ProxySpec.egress` is the number `abox up` prints and the list doctor's
    shared-address analysis examines; the map in the rendered proxy.conf is the
    allowlist. With `run.connectors` on, the map carried a host the spec did not
    — an allowed, connected domain that every report treated as blocked.
    """
    manifest.run.connectors = True
    render.write(render.render(manifest, proxied, workspace, spec))
    mapped = doctor.proxy_allowlist(workspace)
    assert mapped is not None
    assert "mcp-proxy.anthropic.com" in mapped
    assert set(proxy.build_spec(manifest, proxied, workspace).egress) == set(mapped)


def test_fingerprint_covers_the_allowlist(manifest, proxied, workspace, spec) -> None:
    render.write(render.render(manifest, proxied, workspace, spec))
    before = proxy.build_spec(manifest, proxied, workspace).fingerprint()
    manifest.egress = [*manifest.egress, "example.com"]
    assert proxy.build_spec(manifest, proxied, workspace).fingerprint() != before


def _staged_container_states(monkeypatch, container: str) -> None:
    """`docker inspect` before the create, then after it.

    The fake runner answers a pattern the same way every time, and `up` inspects
    the container on both sides of `docker run`.
    """
    from abox import dockerx

    states = [
        dockerx.ContainerState(container, exists=False, running=False),
        dockerx.ContainerState(container, exists=True, running=True, status="running"),
    ]

    def fake(name: str) -> dockerx.ContainerState:
        return states.pop(0) if len(states) > 1 else states[0]

    monkeypatch.setattr(proxy.dockerx, "container_state", fake)


def test_an_unpinned_proxy_image_is_pulled_not_adopted(
    manifest, proxied, workspace, spec, runner, monkeypatch
) -> None:
    """`image_present` is a local `docker image inspect`, so anything able to
    tag an image `nginx:alpine` on this daemon became the process deciding which
    SNIs are allowed — no pull, no digest, no signature check."""
    render.write(render.render(manifest, proxied, workspace, spec))
    _staged_container_states(monkeypatch, proxy.proxy_container("demo"))
    runner.expect(r"docker image inspect", '{"Id": "sha256:local"}')  # already there
    proxy.up(manifest, proxied, workspace)
    assert runner.find("docker pull nginx:alpine")


def test_a_digest_pinned_proxy_image_is_used_from_the_daemon(
    manifest, proxied, workspace, spec, runner, monkeypatch
) -> None:
    """The other half: a digest names its own content, so a local copy is the
    image it claims to be and needs no pull. Without this the rule above would
    be 'always pull', which proves nothing about pinning."""
    proxied.egress_proxy.image = "nginx@sha256:" + "e" * 64
    render.write(render.render(manifest, proxied, workspace, spec))
    _staged_container_states(monkeypatch, proxy.proxy_container("demo"))
    runner.expect(r"docker image inspect", '{"Id": "sha256:local"}')
    proxy.up(manifest, proxied, workspace)
    assert not runner.find("docker pull")


def test_an_unpinned_proxy_image_fails_closed_when_the_pull_fails(
    manifest, proxied, workspace, spec, runner, monkeypatch
) -> None:
    """Falling back to the local tag here would be exactly the substitution the
    pull exists to prevent."""
    render.write(render.render(manifest, proxied, workspace, spec))
    _staged_container_states(monkeypatch, proxy.proxy_container("demo"))
    runner.expect(r"docker image inspect", '{"Id": "sha256:local"}')
    runner.expect(r"docker pull", "", returncode=1, stderr="no route to host")
    with pytest.raises(AboxError, match="could not pull the egress proxy image") as exc:
        proxy.up(manifest, proxied, workspace)
    assert "sha256" in (exc.value.hint or "")
    assert not runner.find("docker run -d")


def test_up_refuses_without_a_rendered_config(manifest, proxied, workspace, runner) -> None:
    with pytest.raises(AboxError, match="no proxy config rendered") as exc:
        proxy.up(manifest, proxied, workspace)
    assert "abox up" in (exc.value.hint or "")


# -- doctor ----------------------------------------------------------------


def test_doctor_fails_when_the_proxy_is_configured_but_down(
    manifest, proxied, workspace, runner
) -> None:
    runner.expect(r"docker container inspect", "", returncode=1)
    checks = {c.id: c for c in doctor.check_egress_proxy(manifest, proxied, workspace)}
    assert checks["egress.proxy"].status is doctor.Status.fail


def test_doctor_is_silent_when_the_proxy_is_off(manifest, config, workspace) -> None:
    assert doctor.check_egress_proxy(manifest, config, workspace) == []


def test_shared_addresses_stop_mattering_with_the_proxy(manifest, proxied, runner) -> None:
    """Sharing an address grants nothing once the decision is made by name."""
    import socket

    real = socket.getaddrinfo
    socket.getaddrinfo = lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.7", 0))
    ]
    try:
        check = doctor.check_shared_addresses(manifest, proxied)
    finally:
        socket.getaddrinfo = real
    assert check.status is doctor.Status.ok
    assert "decides by name" in check.detail


def test_an_unreadable_sni_log_is_not_reported_as_no_denials(manifest, runner) -> None:
    """A stopped or removed proxy fails the exec. Returning [] made that
    indistinguishable from a clean run, and the denial report only speaks when
    the list is non-empty — so the evidence simply vanished."""
    runner.expect(r"cat /var/log/nginx/sni.log", "", returncode=1, stderr="No such container")
    log = proxy.read_denials("demo")
    assert not log.ok
    assert log.entries == ()
    assert "could not read" in log.detail and "No such container" in log.detail


def test_a_readable_empty_sni_log_reports_no_denials(manifest, runner) -> None:
    """The positive path: readable and empty is a real answer, and must not read
    as a failure — otherwise the new state is as uninformative as the old one."""
    runner.expect(r"cat /var/log/nginx/sni.log", "")
    log = proxy.read_denials("demo")
    assert log.ok
    assert log.entries == ()
    assert log.detail == ""


def test_denied_names_parses_refusals(manifest, runner) -> None:
    runner.expect(
        r"cat /var/log/nginx/sni.log",
        '2026-07-23T23:33:39+00:00 client=172.18.0.4 sni="example.com" '
        'upstream="104.20.23.154:443" status=200 bytes=6436\n'
        '2026-07-23T23:33:39+00:00 client=172.18.0.4 sni="pypi.org" '
        'upstream="-" status=500 bytes=0\n',
    )
    denied = proxy.denied_names("demo")
    assert [d["sni"] for d in denied] == ["pypi.org"]
