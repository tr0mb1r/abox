"""Filesystem layout: global config, per-project state, project identity hashes.

Every path used by abox is derived here so tests can redirect the whole tree with
two environment variables (``ABOX_CONFIG_HOME`` / ``ABOX_STATE_HOME``) instead of
monkeypatching call sites.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

MANIFEST_NAME = "agentbox.yaml"
DEVCONTAINER_DIR = ".devcontainer"

#: Length of the hex digest slice used in volume names and state dir names.
HASH_LEN = 12


def config_home() -> Path:
    """Global config dir — ``~/.config/abox`` unless overridden."""
    if override := os.environ.get("ABOX_CONFIG_HOME"):
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return base / "abox"


def state_home() -> Path:
    """Global state dir — ``~/.local/state/abox`` unless overridden."""
    if override := os.environ.get("ABOX_STATE_HOME"):
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "state"
    return base / "abox"


def global_config_path() -> Path:
    return config_home() / "config.yaml"


def secrets_config_path() -> Path:
    return config_home() / "secrets.yaml"


def custom_servers_path() -> Path:
    return config_home() / "custom-servers.yaml"


def project_hash(workspace: Path) -> str:
    """Stable identity for a project directory.

    Derived from the resolved absolute path so that two checkouts of the same
    repo in different directories get different auth volumes and state dirs —
    moving a project is a deliberate re-auth, not a silent credential share.
    """
    resolved = str(workspace.expanduser().resolve())
    return hashlib.sha256(resolved.encode()).hexdigest()[:HASH_LEN]


def project_state_dir(workspace: Path) -> Path:
    return state_home() / project_hash(workspace)


def runs_dir(workspace: Path) -> Path:
    return project_state_dir(workspace) / "runs"


def current_run_dir(workspace: Path) -> Path:
    """Where one run's logs land after being harvested out of the container."""
    return project_state_dir(workspace) / "current-run"


def empty_mask_file(workspace: Path) -> Path:
    """Zero-byte file bind-mounted read-only over masked files."""
    return project_state_dir(workspace) / "empty"


def empty_mask_dir(workspace: Path) -> Path:
    """Empty directory bind-mounted read-only over masked directories."""
    return project_state_dir(workspace) / "empty.d"


def manifest_path(workspace: Path) -> Path:
    return workspace / MANIFEST_NAME


def devcontainer_dir(workspace: Path) -> Path:
    return workspace / DEVCONTAINER_DIR


def mcp_volume(workspace: Path) -> str:
    """Per-project volume carrying mcp.json — and with it the gateway token.

    Not a bind. Everything else abox mounts is a bind of a host file, which
    means the host mode has to satisfy two parties at once: the container, which
    reads as its own uid, and every other account on the machine, which should
    not read a bearer token for a service that holds the Docker socket. Those
    pull opposite ways, and Docker Desktop hid the conflict by ignoring the mode
    entirely. A volume has no such tension: the host copy stays 0400, and the
    copy the agent reads is owned by the agent inside Docker's own storage.
    """
    return f"abox-mcp-{project_hash(workspace)}"


def claude_volume(workspace: Path) -> str:
    """Per-project named volume holding ``~/.claude`` (auth + session state)."""
    return f"abox-claude-{project_hash(workspace)}"


def gateway_container(profile: str) -> str:
    return f"abox-gw-{profile}"


def agent_container(project: str, run_id: str) -> str:
    return f"agent-{project}-{run_id}"


def find_workspace(start: Path | None = None) -> Path:
    """Walk up from ``start`` looking for an ``agentbox.yaml``.

    Falls back to ``start`` itself so ``abox init`` works in a bare directory.
    """
    cur = (start or Path.cwd()).expanduser().resolve()
    for candidate in (cur, *cur.parents):
        if (candidate / MANIFEST_NAME).is_file():
            return candidate
    return cur


def ensure_project_state(workspace: Path) -> Path:
    """Create the per-project state tree (0700) and return its root."""
    root = project_state_dir(workspace)
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o700)
    runs = runs_dir(workspace)
    runs.mkdir(parents=True, exist_ok=True)
    runs.chmod(0o700)
    # Bind-mounted over a masked directory, so the agent lists it as its own uid
    # — 0555 for the same reason empty_mask_file is 0444. It is empty by
    # definition; there is nothing to keep private, only something to shadow.
    empty_dir = empty_mask_dir(workspace)
    empty_dir.mkdir(parents=True, exist_ok=True)
    empty_dir.chmod(0o555)
    # Destination for logs harvested out of the container at teardown. It is not
    # mounted into the container: Docker Desktop does not enforce uid or mode on
    # a bind, so a shared log dir would let the agent edit its own audit trail.
    run_dir = current_run_dir(workspace)
    run_dir.mkdir(parents=True, exist_ok=True)
    run_dir.chmod(0o700)
    empty = empty_mask_file(workspace)
    if not empty.exists():
        empty.touch()
    # Bind-mounted over a masked path and read by the agent as its own uid, so
    # it has to be world-readable on Linux. Zero bytes: there is nothing here to
    # keep private, only something to shadow.
    empty.chmod(0o444)
    return root
