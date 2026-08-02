"""The SNI-aware egress proxy — one container per project on ``abox-net``.

The firewall can only match addresses. That is enough to stop the agent
reaching an arbitrary host, and not enough to stop it reaching a *different*
host at an allowed address: ``pypi.org`` and ``files.pythonhosted.org`` share
four Fastly IPs, and so does everything else Fastly serves. Swap the SNI and the
ipset cannot tell.

So the agent's firewall stops allowlisting addresses at all when the proxy is
on. It permits exactly one destination — this container — and redirects every
outbound 443 connection to it. nginx reads the server name out of the TLS
ClientHello, looks it up in a map rendered from the manifest, and either
connects onward or closes.

Three properties worth stating:

* **TLS is not terminated.** There is no CA to install in the agent, no
  certificate to trust, and nothing inside the tunnel is visible to abox. Only
  the destination name is read, from the one part of the handshake that is
  deliberately in the clear.
* **The proxy is not reachable by the agent as a filesystem or a process.** It
  is a separate container. Its config is mounted read-only and its logs are
  somewhere the agent has no path to at all.
* **It fails closed.** A name absent from the map has no upstream, and nginx
  closes the connection — while still logging the SNI that was attempted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from . import dockerx, paths
from .errors import AboxError
from .manifest import GlobalConfig, Manifest, merged_egress

CONTAINER_CONF = "/etc/nginx/nginx.conf"
LOG_DIR = "/var/log/nginx"
#: Where an unmatched server name is sent. Nothing listens on port 1 of the
#: proxy's own loopback, so the connection is refused immediately — but it is
#: refused *through the normal proxy path*, which means nginx runs its log phase
#: and the attempt reaches the review queue.
#:
#: The map used to default to an empty upstream, which nginx treats as a config
#: error. That also refused the connection, but whether the access log runs on
#: that error path is not guaranteed — it does on nginx 1.31.3 via Docker
#: Desktop and does not on the nginx:alpine a Linux runner pulls, so denials
#: vanished from the queue on Linux while the refusal itself still worked.
#: Failing closed was never in doubt; being *able to see it* was.
DENY_SENTINEL = "127.0.0.1:1"

#: The unprivileged user nginx:alpine ships.
NGINX_UID = 101
NGINX_GID = 101


def proxy_container(project: str) -> str:
    return f"abox-proxy-{project}"


def conf_path(workspace: Path) -> Path:
    from .render import artifacts_path

    return artifacts_path(workspace) / "proxy.conf"


@dataclass(frozen=True)
class ProxySpec:
    project: str
    container: str
    image: str
    port: int
    network: str
    conf: Path
    egress: tuple[str, ...]
    #: Is ``image`` a digest reference? A digest names its own content, so a
    #: local copy of one can be adopted; a tag names whatever happens to carry
    #: it on this daemon.
    image_pinned: bool = False

    def run_options(self) -> list[str]:
        """Nothing published: the agent reaches this by container DNS only."""
        return [
            "--network",
            self.network,
            "--restart",
            "unless-stopped",
            "--label",
            f"{dockerx.LABEL_MANAGED}=true",
            "--label",
            f"{dockerx.LABEL_ROLE}=proxy",
            "--label",
            f"{dockerx.LABEL_PROJECT}={self.project}",
            # Run *as* nginx rather than letting nginx drop privileges: with
            # every capability dropped the master cannot setgid, so it would
            # hold the listening socket while its worker died on startup.
            "--user",
            f"{NGINX_UID}:{NGINX_GID}",
            "--read-only",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,uid={NGINX_UID},gid={NGINX_GID}",  # noqa: S108
            "--tmpfs",
            f"{LOG_DIR}:rw,noexec,nosuid,uid={NGINX_UID},gid={NGINX_GID}",
            "--cap-drop",
            "ALL",
            "-v",
            f"{self.conf}:{CONTAINER_CONF}:ro",
        ]

    def fingerprint(self) -> str:
        """Everything that, if changed, means the container must be recreated.

        Includes the run options: a change in *how* abox runs the proxy — a
        different user, a dropped capability — is as much a reason to recreate
        it as a changed allowlist, and leaving it out means an upgrade silently
        keeps the old container.
        """
        return json.dumps(
            {
                "image": self.image,
                "port": self.port,
                "network": self.network,
                "egress": list(self.egress),
                "run_options": self.run_options(),
                "conf": self.conf.read_text(encoding="utf-8")
                if self.conf.is_file()
                else "",
            },
            sort_keys=True,
        )


def build_spec(manifest: Manifest, config: GlobalConfig, workspace: Path) -> ProxySpec:
    return ProxySpec(
        project=manifest.project,
        container=proxy_container(manifest.project),
        image=config.egress_proxy.image,
        port=config.egress_proxy.port,
        network=config.network,
        conf=conf_path(workspace),
        egress=tuple(merged_egress(manifest, config)),
        image_pinned=config.egress_proxy.pinned,
    )


@dataclass(frozen=True)
class ProxyStatus:
    project: str
    container: str
    exists: bool
    running: bool
    detail: str
    egress: tuple[str, ...] = ()
    published_ports: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.running


def _fingerprint_path(project: str) -> Path:
    directory = paths.state_home() / "proxies"
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)
    return directory / f"{project}.fingerprint"


def status(manifest: Manifest, config: GlobalConfig, workspace: Path) -> ProxyStatus:
    spec = build_spec(manifest, config, workspace)
    state = dockerx.container_state(spec.container)
    if not state.exists:
        return ProxyStatus(
            spec.project, spec.container, False, False, "not created", spec.egress
        )
    return ProxyStatus(
        spec.project,
        spec.container,
        True,
        state.running,
        "running" if state.running else f"container {state.status}",
        spec.egress,
        tuple(state.published_ports),
    )


def up(
    manifest: Manifest,
    config: GlobalConfig,
    workspace: Path,
    *,
    force: bool = False,
) -> ProxyStatus:
    """Start or reconcile the project's egress proxy."""
    spec = build_spec(manifest, config, workspace)
    if not spec.conf.is_file():
        raise AboxError(
            f"no proxy config rendered at {spec.conf}",
            hint="run `abox up` to render the artifacts first",
        )
    dockerx.ensure_network(spec.network)

    stored = (
        _fingerprint_path(spec.project).read_text(encoding="utf-8").strip()
        if _fingerprint_path(spec.project).is_file()
        else None
    )
    state = dockerx.container_state(spec.container)
    if state.exists and (force or stored != spec.fingerprint() or not state.running):
        dockerx.remove(spec.container)
        state = dockerx.container_state(spec.container)

    if not state.exists:
        # This container decides which names leave the sandbox and sees the SNI
        # of every connection the agent makes, so an unpinned reference must not
        # be satisfied by whatever already carries that tag on the daemon:
        # `image_present` is a local `docker image inspect`, so a
        # `docker build -t nginx:alpine` — or a poisoned base on a shared CI host
        # — was adopted as the egress filter with no pull and no digest.
        if not spec.image_pinned or not dockerx.image_present(spec.image):
            pull = dockerx.pull(spec.image)
            if not pull.ok:
                raise AboxError(
                    f"could not pull the egress proxy image {spec.image}: "
                    f"{pull.stderr.strip()[:200]}",
                    hint="pin it by digest (`egress_proxy.image: nginx@sha256:…` in "
                    "~/.config/abox/config.yaml) and abox will use a local copy "
                    "without needing the registry",
                )
        dockerx.run_detached(spec.container, spec.image, [], opts=spec.run_options())
        path = _fingerprint_path(spec.project)
        path.write_text(spec.fingerprint(), encoding="utf-8")
        path.chmod(0o600)

    current = status(manifest, config, workspace)
    if not current.running:
        logs = dockerx.logs(spec.container, tail=20)
        raise AboxError(
            f"the egress proxy {spec.container} did not stay up",
            hint=f"`docker logs {spec.container}` tail:\n{logs[-800:]}",
        )
    return replace(current, detail=f"filtering {len(spec.egress)} domain(s) by SNI")


def down(project: str) -> bool:
    container = proxy_container(project)
    if not dockerx.container_state(container).exists:
        return False
    dockerx.remove(container)
    return True


@dataclass(frozen=True)
class DenialLog:
    """The SNI log as read — including the case where it could not be read.

    "nothing was denied" and "the log is unreadable" are different answers, and
    they used to be the same empty list: a stopped, removed or exec-refused
    proxy returned ``[]`` and the report that only speaks when the list is
    non-empty said nothing at all. In proxy mode this is the only domain-level
    denial evidence there is, so silence has to be distinguishable from clean.
    """

    ok: bool
    detail: str = ""
    entries: tuple[dict[str, Any], ...] = ()


def read_denials(project: str, *, tail: int = 500) -> DenialLog:
    """SNI values the proxy refused, or why they could not be read.

    This is the domain-level counterpart to the DNS review queue: a name here
    was not merely looked up, it was connected to.

    A refusal is recognised by the sentinel upstream, and still by the older
    empty/"-" form so a log written before this change keeps parsing.
    """
    result = dockerx.docker(
        "exec", proxy_container(project), "cat", f"{LOG_DIR}/sni.log", timeout=30
    )
    if not result.ok:
        detail = (result.stderr or result.stdout).strip().splitlines()
        return DenialLog(
            False,
            f"could not read {LOG_DIR}/sni.log in {proxy_container(project)}: "
            f"{detail[-1] if detail else 'docker exec failed'}",
        )
    out: list[dict[str, Any]] = []
    for line in result.stdout.splitlines()[-tail:]:
        if 'upstream="-"' not in line and "status=200" in line:
            continue
        fields: dict[str, Any] = {}
        for token in line.split():
            if "=" in token:
                key, _, value = token.partition("=")
                fields[key] = value.strip('"')
        sni = fields.get("sni", "")
        if sni and sni != "-" and fields.get("upstream", "-") in ("-", "", DENY_SENTINEL):
            out.append({"sni": sni, "client": fields.get("client", ""), "raw": line})
    return DenialLog(True, "", tuple(out))


def denied_names(project: str, *, tail: int = 500) -> list[dict[str, Any]]:
    """Just the refusals, for callers that cannot act on a read failure.

    This collapses "unreadable" back into "empty", so anything that *reports* to
    an operator wants `read_denials` instead.
    """
    return list(read_denials(project, tail=tail).entries)
