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


def test_fingerprint_covers_the_allowlist(manifest, proxied, workspace, spec) -> None:
    render.write(render.render(manifest, proxied, workspace, spec))
    before = proxy.build_spec(manifest, proxied, workspace).fingerprint()
    manifest.egress = [*manifest.egress, "example.com"]
    assert proxy.build_spec(manifest, proxied, workspace).fingerprint() != before


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
