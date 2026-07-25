"""Thin, typed wrappers over the ``docker`` CLI.

abox drives Docker through its CLI rather than the API socket on purpose: the
host tool should need no more privilege than the operator already has, and the
argv of every action stays inspectable in ``abox --verbose`` output.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from . import shell
from .errors import DockerError

LABEL_MANAGED = "abox.managed"
LABEL_ROLE = "abox.role"
LABEL_PROFILE = "abox.profile"
LABEL_PROJECT = "abox.project"
LABEL_RUN = "abox.run"


def docker(*args: str, **kwargs: object) -> shell.Result:
    return shell.run(["docker", *args], **kwargs)


def available() -> bool:
    return shell.which("docker") is not None


def daemon_ok() -> tuple[bool, str]:
    """Is a Docker daemon reachable? Returns (ok, detail)."""
    if not available():
        return False, "docker CLI not on PATH"
    result = docker("version", "--format", "{{.Server.Version}}", timeout=30)
    if not result.ok:
        return False, (result.stderr or result.stdout).strip().splitlines()[-1:][0] if (
            result.stderr or result.stdout
        ).strip() else "docker daemon not reachable"
    return True, result.stdout.strip()


def inspect(kind: str, name: str) -> dict[str, Any] | None:
    """``docker <kind> inspect`` returning the first object, or None."""
    result = docker(kind, "inspect", name, "--format", "{{json .}}", timeout=60)
    if not result.ok:
        return None
    try:
        return json.loads(result.stdout.strip() or "null")
    except json.JSONDecodeError:
        return None


# -- networks -------------------------------------------------------------


def network_exists(name: str) -> bool:
    return inspect("network", name) is not None


def ensure_network(name: str) -> bool:
    """Create the user bridge if absent. Returns True when it created it.

    Deliberately *not* ``--internal``: agents need internet egress, and that
    egress is governed by the in-container firewall, not by Docker.
    """
    if network_exists(name):
        return False
    result = docker(
        "network",
        "create",
        "--driver",
        "bridge",
        "--label",
        f"{LABEL_MANAGED}=true",
        name,
        timeout=60,
    )
    if not result.ok:
        # Lost a race with a concurrent `abox up`? Then it exists now; fine.
        if network_exists(name):
            return False
        raise DockerError(
            f"could not create network {name!r}: {result.stderr.strip()[:200]}",
            hint="check `docker network ls` for a conflicting network",
        )
    return True


# -- containers -----------------------------------------------------------


@dataclass(frozen=True)
class ContainerState:
    name: str
    exists: bool
    running: bool
    status: str = ""
    image: str = ""
    started_at: str = ""
    health: str = ""
    labels: dict[str, str] | None = None
    ports: dict[str, Any] | None = None

    @property
    def published_ports(self) -> list[str]:
        """Host-published port bindings — must always be empty for abox."""
        out: list[str] = []
        for port, bindings in (self.ports or {}).items():
            if bindings:
                for binding in bindings:
                    out.append(f"{binding.get('HostIp', '')}:{binding.get('HostPort', '')}->{port}")
        return out


def container_state(name: str) -> ContainerState:
    data = inspect("container", name)
    if not data:
        return ContainerState(name=name, exists=False, running=False)
    state = data.get("State") or {}
    config = data.get("Config") or {}
    netsettings = data.get("NetworkSettings") or {}
    return ContainerState(
        name=name,
        exists=True,
        running=bool(state.get("Running")),
        status=str(state.get("Status") or ""),
        image=str(config.get("Image") or ""),
        started_at=str(state.get("StartedAt") or ""),
        health=str((state.get("Health") or {}).get("Status") or ""),
        labels=dict(config.get("Labels") or {}),
        ports=dict(netsettings.get("Ports") or {}),
    )


def run_detached(name: str, image: str, args: Sequence[str], *, opts: Sequence[str]) -> str:
    """``docker run -d`` — returns the container id."""
    argv = ["run", "-d", "--name", name, *opts, image, *args]
    result = docker(*argv, timeout=180)
    if not result.ok:
        raise DockerError(
            f"could not start container {name!r}: {result.stderr.strip()[:400]}",
            hint=f"docker {' '.join(argv)}",
        )
    return result.stdout.strip()


def stop(name: str, *, timeout: int = 10) -> bool:
    result = docker("stop", "-t", str(timeout), name, timeout=timeout + 30)
    return result.ok


def remove(name: str, *, force: bool = True) -> bool:
    argv = ["rm", "-f", name] if force else ["rm", name]
    return docker(*argv, timeout=60).ok


def logs(name: str, *, tail: int = 200, since: str | None = None) -> str:
    argv = ["logs", "--tail", str(tail)]
    if since:
        argv += ["--since", since]
    argv.append(name)
    result = docker(*argv, timeout=60)
    return result.stdout + result.stderr


def list_managed(role: str | None = None) -> list[str]:
    filters = ["--filter", f"label={LABEL_MANAGED}=true"]
    if role:
        filters += ["--filter", f"label={LABEL_ROLE}={role}"]
    result = docker("ps", "-a", *filters, "--format", "{{.Names}}", timeout=60)
    return result.lines


# -- images ---------------------------------------------------------------


def image_present(image: str) -> bool:
    return inspect("image", image) is not None


def pull(image: str) -> shell.Result:
    return docker("pull", image, timeout=600)


def image_digest(image: str) -> str | None:
    """Return ``repo@sha256:…`` for a locally present image."""
    data = inspect("image", image)
    if not data:
        return None
    digests = data.get("RepoDigests") or []
    if digests:
        return str(digests[0])
    return None


def container_image_digest(name: str) -> str | None:
    """Return the ``repo@sha256:…`` a running container was actually started from.

    ``Config.Image`` records the reference the operator typed, which is exactly
    the thing that can lie when it is a tag. The image *id* cannot, so resolve
    through it.
    """
    data = inspect("container", name)
    if not data:
        return None
    image_id = str(data.get("Image") or "")
    if not image_id:
        return None
    return image_digest(image_id)


# -- volumes --------------------------------------------------------------


def volume_exists(name: str) -> bool:
    return inspect("volume", name) is not None


def ensure_volume(name: str, *, labels: dict[str, str] | None = None) -> bool:
    if volume_exists(name):
        return False
    argv = ["volume", "create"]
    for key, value in {LABEL_MANAGED: "true", **(labels or {})}.items():
        argv += ["--label", f"{key}={value}"]
    argv.append(name)
    result = docker(*argv, timeout=60)
    if not result.ok:
        raise DockerError(f"could not create volume {name!r}: {result.stderr.strip()[:200]}")
    return True


def remove_volume(name: str) -> bool:
    return docker("volume", "rm", name, timeout=60).ok
