"""Secret sources → the Docker secret store, one-way.

abox does not require 1Password. A secret can come from any of:

* ``op://…``          — 1Password CLI, if the operator uses it
* a **file** on the host — refused if it is readable by anyone else
* an **environment variable** on the host
* **typed at the terminal** — never echoed, never written to disk by abox
* **already in the Docker store** — abox verifies presence and stays out of the way

Whatever the source, the same two rules hold:

* A value moves between processes over a **pipe**, never over argv (argv is
  visible in ``ps`` to every user on the box) and never via a temp file.
* Freshness tracking stores a **salted** digest, never the value and never a
  bare ``sha256`` — a bare digest of a low-entropy secret is crackable offline,
  and this file has the same blast radius as the secret it describes.

The Docker daemon, not the gateway process, resolves ``se://docker/mcp/<name>``
into the MCP server container. So a stored secret is usable by the gateway
without the gateway (or the agent) ever holding the value.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import secrets as pysecrets
import stat
import time
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from . import paths, shell
from .catalog import Catalog
from .errors import AboxError, SecretsError
from .manifest import SecretMapping, SecretsConfig, SecretSource

DOCKER_SECRET_PREFIX = "docker/mcp/"  # noqa: S105 - a name prefix, not a credential


def state_path() -> Path:
    return paths.state_home() / "secrets.json"


def salt_path() -> Path:
    return paths.state_home() / "secrets.salt"


def _ensure_state_home() -> Path:
    root = paths.state_home()
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o700)
    return root


def _salt() -> bytes:
    _ensure_state_home()
    path = salt_path()
    if path.is_file():
        data = path.read_bytes().strip()
        if len(data) >= 16:
            return data
    salt = pysecrets.token_bytes(32).hex().encode()
    path.write_bytes(salt)
    path.chmod(0o600)
    return salt


def digest(value: str) -> str:
    """Salted digest used for drift detection. Never reversible to the value."""
    return hashlib.sha256(_salt() + value.encode()).hexdigest()


# -- state ----------------------------------------------------------------


@dataclass
class SyncState:
    """``secret name -> {digest, synced_at, source, reference}``."""

    entries: dict[str, dict[str, str]]

    @classmethod
    def load(cls) -> SyncState:
        path = state_path()
        if not path.is_file():
            return cls(entries={})
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return cls(entries={})
        return cls(entries=dict(data.get("secrets") or {}))

    def save(self) -> None:
        _ensure_state_home()
        path = state_path()
        path.write_text(json.dumps({"secrets": self.entries}, indent=2) + "\n", encoding="utf-8")
        path.chmod(0o600)

    def record(self, name: str, *, value_digest: str, source: str, reference: str) -> None:
        self.entries[name] = {
            "digest": value_digest,
            "source": source,
            "reference": reference,
            "synced_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    def digest_of(self, name: str) -> str | None:
        entry = self.entries.get(name)
        return entry.get("digest") if entry else None


# -- providers ------------------------------------------------------------


def op_available() -> bool:
    return shell.which("op") is not None


def read_from_op(ref: str) -> str:
    if not op_available():
        raise SecretsError(
            "this mapping uses a 1Password reference but the `op` CLI is not installed",
            hint="brew install 1password-cli and `op signin`, or switch the mapping to "
            "file:/env:/source: prompt in ~/.config/abox/secrets.yaml",
        )
    result = shell.run(["op", "read", "--no-newline", ref], timeout=60)
    if not result.ok:
        detail = (result.stderr or result.stdout).strip().splitlines()
        raise SecretsError(
            f"could not read {ref}: {detail[-1] if detail else 'unknown error'}",
            hint="check the reference with `op read <ref>` and that the session or "
            "service-account token is valid",
        )
    return result.stdout


def read_from_file(spec: str, *, allow_loose_perms: bool = False) -> str:
    """Read a secret from a host file, refusing one anyone else can read."""
    path = Path(spec).expanduser()
    if not path.is_file():
        raise SecretsError(
            f"secret file not found: {path}",
            hint="create it with `printf %s '<value>' > <file> && chmod 600 <file>`",
        )
    mode = path.stat().st_mode
    if (mode & (stat.S_IRWXG | stat.S_IRWXO)) and not allow_loose_perms:
        raise SecretsError(
            f"secret file {path} is readable by group or others (mode "
            f"{stat.filemode(mode)})",
            hint=f"chmod 600 {path} — or pass --allow-loose-perms if you accept the risk",
        )
    value = path.read_text(encoding="utf-8")
    # A trailing newline from `echo` is almost never part of the credential.
    return value.rstrip("\n")


def read_from_env(name: str) -> str:
    value = os.environ.get(name)
    if value is None:
        raise SecretsError(
            f"environment variable {name} is not set",
            hint=f"export {name}=… in the shell you run `abox secrets sync` from",
        )
    return value


def read_from_prompt(name: str, *, reference: str = "") -> str:
    """Read from the terminal without echo. Nothing is written to disk by abox."""
    if not os.isatty(0):
        raise SecretsError(
            f"secret {name!r} is configured to be typed in, but stdin is not a terminal",
            hint="run `abox secrets set " + name + "` interactively, or pipe the value: "
            f"`printf %s '<value>' | abox secrets set {name} --stdin`",
        )
    label = f"value for {name}" + (f" ({reference})" if reference else "")
    value = getpass.getpass(f"{label}: ")
    if not value:
        raise SecretsError(f"no value entered for {name!r}")
    return value


def read_value(mapping: SecretMapping, *, allow_loose_perms: bool = False) -> str:
    """Obtain the value for one mapping. The value stays in memory."""
    match mapping.kind:
        case SecretSource.op:
            value = read_from_op(mapping.op or "")
        case SecretSource.file:
            value = read_from_file(mapping.file or "", allow_loose_perms=allow_loose_perms)
        case SecretSource.env:
            value = read_from_env(mapping.env or "")
        case SecretSource.prompt:
            value = read_from_prompt(mapping.secret)
        case SecretSource.docker:
            raise SecretsError(
                f"secret {mapping.secret!r} is managed outside abox (source: docker)",
                hint="abox verifies it exists but cannot read or refresh it",
            )
    if not value.strip():
        raise SecretsError(f"source for {mapping.secret!r} returned an empty value")
    return value


# -- docker secret store --------------------------------------------------


def docker_secret_names() -> set[str]:
    """Names currently in the Docker secret store, unprefixed."""
    result = shell.run(["docker", "mcp", "secret", "ls"], timeout=60)
    if not result.ok:
        raise SecretsError(
            f"could not list docker secrets: {result.stderr.strip()[:200]}",
            hint="is Docker Desktop running with the MCP Toolkit enabled?",
        )
    names: set[str] = set()
    for line in result.lines:
        head = line.split("|", 1)[0].strip()
        if not head or head.lower().startswith("name"):
            continue
        names.add(head.removeprefix(DOCKER_SECRET_PREFIX))
    return names


def docker_secret_set(name: str, value: str) -> None:
    """Write one secret via stdin. The value never appears in argv."""
    result = shell.run_piped(["docker", "mcp", "secret", "set", name], value, timeout=60)
    if not result.ok:
        detail = (result.stderr or result.stdout).strip().splitlines()
        raise SecretsError(
            f"could not store docker secret {name!r}: "
            f"{detail[-1] if detail else 'unknown error'}"
        )


def docker_secret_rm(name: str) -> bool:
    return shell.run(["docker", "mcp", "secret", "rm", name], timeout=60).ok


# -- sync / check ---------------------------------------------------------


class SecretStatus(StrEnum):
    synced = "synced"
    created = "created"
    updated = "updated"
    unchanged = "unchanged"
    missing_in_store = "missing-in-store"
    drifted = "drifted"
    unreadable = "unreadable"
    unmapped = "unmapped"
    external = "external"


@dataclass
class SecretReport:
    name: str
    status: SecretStatus
    detail: str = ""
    reference: str = ""
    source: str = ""

    @property
    def ok(self) -> bool:
        return self.status in {
            SecretStatus.synced,
            SecretStatus.created,
            SecretStatus.updated,
            SecretStatus.unchanged,
            SecretStatus.external,
        }


def set_secret(name: str, value: str, *, reference: str = "manual", source: str = "manual") -> None:
    """Store one value and record its digest so drift detection still works."""
    docker_secret_set(name, value)
    state = SyncState.load()
    state.record(name, value_digest=digest(value), source=source, reference=reference)
    state.save()


def sync(
    config: SecretsConfig,
    *,
    only: Iterable[str] | None = None,
    dry_run: bool = False,
    allow_loose_perms: bool = False,
    include_prompts: bool = False,
) -> list[SecretReport]:
    """Push every mapped value into the Docker secret store.

    Sources that cannot be read non-interactively (``prompt``) are skipped
    unless ``include_prompts`` is set, so ``abox secrets sync`` stays usable
    from a script.
    """
    wanted = set(only) if only else None
    state = SyncState.load()
    # Listing is a read, so the preview gets it too: a dry run against a
    # fabricated empty store previewed deleted secrets as `unchanged`, and
    # healthy `source: docker` / `source: prompt` mappings as missing.
    present = docker_secret_names()
    reports: list[SecretReport] = []

    for mapping in config.mappings:
        if wanted and mapping.secret not in wanted:
            continue
        kind = mapping.kind

        if kind is SecretSource.docker:
            in_store = mapping.secret in present
            reports.append(
                SecretReport(
                    mapping.secret,
                    SecretStatus.external if in_store else SecretStatus.missing_in_store,
                    "managed outside abox"
                    if in_store
                    else "declared as source: docker but not in the store",
                    mapping.reference,
                    kind.value,
                )
            )
            continue

        if kind is SecretSource.prompt and not include_prompts:
            reports.append(
                SecretReport(
                    mapping.secret,
                    SecretStatus.unchanged
                    if mapping.secret in present
                    else SecretStatus.unreadable,
                    "interactive source — run `abox secrets set " + mapping.secret + "`",
                    mapping.reference,
                    kind.value,
                )
            )
            continue

        try:
            value = read_value(mapping, allow_loose_perms=allow_loose_perms)
        except SecretsError as exc:
            reports.append(
                SecretReport(
                    mapping.secret,
                    SecretStatus.unreadable,
                    exc.message,
                    mapping.reference,
                    kind.value,
                )
            )
            continue

        new_digest = digest(value)
        old_digest = state.digest_of(mapping.secret)
        in_store = mapping.secret in present

        if dry_run:
            # The same predicate the real path below uses, with the write
            # suppressed — a preview that disagrees with the run it previews is
            # worse than no preview.
            status = (
                SecretStatus.unchanged
                if in_store and old_digest == new_digest
                else (SecretStatus.updated if in_store else SecretStatus.created)
            )
            reports.append(
                SecretReport(mapping.secret, status, "dry run", mapping.reference, kind.value)
            )
            del value
            continue

        if in_store and old_digest == new_digest:
            reports.append(
                SecretReport(
                    mapping.secret,
                    SecretStatus.unchanged,
                    "already current",
                    mapping.reference,
                    kind.value,
                )
            )
            del value
            continue

        docker_secret_set(mapping.secret, value)
        state.record(
            mapping.secret,
            value_digest=new_digest,
            source=kind.value,
            reference=mapping.reference,
        )
        # Persist as we go: a failure on a later mapping used to propagate past
        # the trailing save() and lose the digests already written, leaving
        # `secrets check` and `doctor` reporting permanent drift on current
        # credentials.
        state.save()
        reports.append(
            SecretReport(
                mapping.secret,
                SecretStatus.created if not in_store else SecretStatus.updated,
                "written via stdin",
                mapping.reference,
                kind.value,
            )
        )
        del value

    if not dry_run:
        state.save()
    return reports


def check(
    config: SecretsConfig,
    *,
    required: Iterable[str] | None = None,
    allow_loose_perms: bool = False,
) -> list[SecretReport]:
    """Compare each source against the Docker store without printing any value."""
    state = SyncState.load()
    present = docker_secret_names()
    reports: list[SecretReport] = []
    mapped = {m.secret for m in config.mappings}

    for mapping in config.mappings:
        kind = mapping.kind
        if mapping.secret not in present:
            reports.append(
                SecretReport(
                    mapping.secret,
                    SecretStatus.missing_in_store,
                    "mapped but not in the docker secret store",
                    mapping.reference,
                    kind.value,
                )
            )
            continue
        if not mapping.readable:
            reports.append(
                SecretReport(
                    mapping.secret,
                    SecretStatus.external,
                    "present; source cannot be re-read for drift detection",
                    mapping.reference,
                    kind.value,
                )
            )
            continue
        try:
            value = read_value(mapping, allow_loose_perms=allow_loose_perms)
        except SecretsError as exc:
            reports.append(
                SecretReport(
                    mapping.secret,
                    SecretStatus.unreadable,
                    exc.message,
                    mapping.reference,
                    kind.value,
                )
            )
            continue
        current = digest(value)
        del value
        known = state.digest_of(mapping.secret)
        if known is None:
            status, detail = SecretStatus.drifted, "never synced by abox — run `abox secrets sync`"
        elif known != current:
            status, detail = SecretStatus.drifted, "source value changed since last sync"
        else:
            status, detail = SecretStatus.synced, "current"
        reports.append(
            SecretReport(mapping.secret, status, detail, mapping.reference, kind.value)
        )

    for name in sorted(set(required or ()) - mapped):
        if name in present:
            reports.append(
                SecretReport(
                    name,
                    SecretStatus.external,
                    "present in the docker store (not managed by abox)",
                    source="docker",
                )
            )
        else:
            reports.append(
                SecretReport(
                    name,
                    SecretStatus.unmapped,
                    "required by a declared server but absent from the store and secrets.yaml",
                    source="-",
                )
            )
    return reports


def required_secrets(catalog: Catalog, servers: Iterable[str]) -> list[str]:
    """Secret names the declared servers expect, per the catalog."""
    return catalog.secrets_for(servers)


# -- who uses what ---------------------------------------------------------


@dataclass(frozen=True)
class SecretUse:
    """One place a secret is referenced, for the reverse index."""

    project: str
    workspace: str
    kind: str  # "env" | "server" | "remote" | "mapping"
    detail: str  # the env var name, the server that needs it, or the source

    def __str__(self) -> str:
        return f"{self.project} → {self.kind} {self.detail}"


def usage_index(catalog: Catalog | None = None) -> dict[str, list[SecretUse]]:
    """secret name -> everywhere abox knows it is referenced.

    Covers the three ways a secret gets consumed — handed to the agent as an
    environment variable, required by a declared MCP server, or injected into a
    remote server's headers — plus the mapping in ``secrets.yaml`` that would
    put it back. ``abox secrets rm`` gates on this index, and a removal the very
    next ``abox secrets sync`` silently undoes is not a revocation. Projects
    abox has never seen cannot appear — the index is only as complete as the
    registries.
    """
    from .gateway import known_projects
    from .manifest import Manifest

    index: dict[str, list[SecretUse]] = {}

    def add(name: str, use: SecretUse) -> None:
        index.setdefault(name, []).append(use)

    for mapping in SecretsConfig.load().mappings:
        # `source: docker` is the one mapping sync will not re-push — it only
        # verifies presence — so listing it here would block a removal abox
        # cannot undo, and a standing false refusal trains you past the gate.
        if mapping.kind is not SecretSource.docker:
            add(
                mapping.secret,
                SecretUse(
                    "(global)",
                    str(paths.secrets_config_path()),
                    "mapping",
                    f"{mapping.reference} in {paths.secrets_config_path().name}",
                ),
            )

    for known in known_projects():
        if not known.exists:
            continue
        try:
            manifest = Manifest.load(known.workspace)
        except AboxError:
            # One unreadable manifest must not hide every other project's usage.
            continue
        for env, name in manifest.env_secrets.items():
            add(name, SecretUse(manifest.project, str(known.workspace), "env", env))
        for server_name, server in manifest.remote_servers.items():
            for entry in server.secrets:
                add(
                    entry.name,
                    SecretUse(manifest.project, str(known.workspace), "remote", server_name),
                )
        if catalog is not None:
            for server_name in manifest.servers:
                entry_server = catalog.get(server_name)
                if entry_server is None:
                    continue
                for name in entry_server.secrets:
                    add(
                        name,
                        SecretUse(manifest.project, str(known.workspace), "server", server_name),
                    )
    return index


def stale_projects() -> list[str]:
    """Registered workspaces whose manifest has gone — the index cannot see them."""
    from .gateway import known_projects

    return [str(k.workspace) for k in known_projects() if not k.exists]
