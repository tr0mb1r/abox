"""Pydantic models for the project manifest and the global config.

The schema is the single source of truth for both ``abox init`` (which writes it)
and ``abox doctor`` (which validates it). Anything a boundary check depends on —
permission mode, egress list, mask globs — is modelled here with the strictest
validation that still lets a human hand-edit the file.
"""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from . import paths
from .errors import ConfigError, ManifestNotFoundError

MANIFEST_VERSION = 1

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
#: MCP server names come from the Docker catalog, which is not all-lowercase.
_SERVER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_HOST_LABEL = r"[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
_HOST_RE = re.compile(rf"^{_HOST_LABEL}(\.{_HOST_LABEL})+$")
_DIGEST_RE = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")

#: Toolchains abox knows how to install in the agent image. The install recipes
#: live in ``templates/Dockerfile.j2``; the set is duplicated here so an unknown
#: toolchain is rejected at parse time rather than half-way through a build.
#:
#: None of these are installed with npm on the host — abox has no npm dependency
#: at all. ``node`` installs Node *inside the container* because the project
#: asked for it, from the official tarball.
TOOLCHAINS: frozenset[str] = frozenset(
    {"python", "go", "node", "rust", "java", "ruby", "php", "dotnet"}
)

#: Egress every project gets whether it asks or not: the hosts Claude Code needs
#: to authenticate and run at all, per its documented network requirements. The
#: gateway host is added separately at render time (it is an in-network container
#: name, not a public domain).
#:
#: `platform.claude.com` is the one people miss — OAuth token exchange and
#: refresh go there for claude.ai *and* Console accounts, so a session that works
#: today breaks whenever the token needs refreshing without it.
BASE_MANDATORY_EGRESS: tuple[str, ...] = (
    "api.anthropic.com",  # API requests, WebFetch safety check, feature flags
    "platform.claude.com",  # OAuth token exchange / refresh / revocation
    "claude.ai",  # claude.ai account authentication
    "claude.com",  # sign-in redirect target
)

#: Environment abox controls in the agent container; a secret must not shadow
#: one of these or it would quietly change how the sandbox behaves.
RESERVED_AGENT_ENV: frozenset[str] = frozenset(
    {
        "ABOX_PROJECT",
        "ABOX_PROFILE",
        "ABOX_GATEWAY_URL",
        "ABOX_RUN_LOG_DIR",
        "CLAUDE_CONFIG_DIR",
        "PATH",
        "HOME",
    }
)

#: Reached only when `run.connectors` is on; see `RunConfig.connectors`.
CONNECTOR_EGRESS: tuple[str, ...] = ("mcp-proxy.anthropic.com",)

#: Hosts Claude Code will reach for if left alone, which abox deliberately does
#: NOT allow — paired with the environment variable that stops it trying. A
#: sandbox that blocks a host the agent keeps retrying produces a review queue
#: full of abox's own defaults, which is how a useful signal becomes noise.
OPTIONAL_CLAUDE_TRAFFIC: dict[str, str] = {
    "downloads.claude.ai": "auto-updater and version checks — the image pins a "
    "version deliberately, so updating inside a disposable container would undo it",
    "http-intake.logs.us5.datadoghq.com": "optional operational telemetry",
    "http-intake.logs.datadoghq.com": "optional operational telemetry",
    "mcp-proxy.anthropic.com": "claude.ai MCP connectors — a second MCP path, "
    "which is exactly what the single-endpoint invariant exists to prevent",
    "raw.githubusercontent.com": "release-notes changelog feed",
    "code.claude.com": "documentation lookups",
    "storage.googleapis.com": "plugin metadata and artifact uploads",
}


class PermissionMode(StrEnum):
    default = "default"
    accept_edits = "acceptEdits"
    bypass_permissions = "bypassPermissions"
    plan = "plan"


class OutputFormat(StrEnum):
    stream_json = "stream-json"
    json = "json"
    text = "text"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


Name = Annotated[str, Field(min_length=1, max_length=64)]


def _check_name(value: str, what: str) -> str:
    """Names that become Docker object names, so they must be lowercase."""
    if not _NAME_RE.match(value):
        raise ValueError(
            f"{what} must match {_NAME_RE.pattern} (lowercase, digits, dot, dash, underscore)"
        )
    return value


def _check_server_name(value: str, what: str = "server name") -> str:
    """Names that only ever become a ``--servers=`` element.

    The Docker MCP catalog is not all-lowercase — ``SQLite`` is a real registry
    key — so this must accept what the catalog actually ships. It stays strict
    about everything that would make the name unsafe to concatenate into an
    argument list: no spaces, no commas, no path or shell metacharacters.
    """
    if not _SERVER_NAME_RE.match(value):
        raise ValueError(
            f"{what} must match {_SERVER_NAME_RE.pattern} "
            "(letters, digits, dot, dash, underscore)"
        )
    return value


def _check_host(value: str) -> str:
    v = value.strip().lower()
    if "://" in v:
        raise ValueError(f"egress entries are bare hostnames, not URLs: {value!r}")
    if "/" in v:
        raise ValueError(f"egress entries must not contain a path: {value!r}")
    if ":" in v:
        raise ValueError(f"egress entries must not contain a port: {value!r}")
    if "*" in v:
        raise ValueError(
            f"wildcard egress is not supported: {value!r} — "
            "the firewall resolves each name into an ipset, so every host must be explicit"
        )
    if not _HOST_RE.match(v):
        raise ValueError(f"not a valid hostname: {value!r}")
    return v


class MountsConfig(StrictModel):
    """Filesystem shaping for the agent container."""

    mask: list[str] = Field(default_factory=list)
    context: list[str] = Field(default_factory=list)

    @field_validator("mask")
    @classmethod
    def _validate_mask(cls, value: list[str]) -> list[str]:
        for glob in value:
            if glob.startswith("/"):
                raise ValueError(f"mask globs are workspace-relative: {glob!r}")
            if ".." in Path(glob).parts:
                raise ValueError(f"mask globs must not escape the workspace: {glob!r}")
        return value

    @field_validator("context")
    @classmethod
    def _validate_context(cls, value: list[str]) -> list[str]:
        for entry in value:
            p = Path(entry).expanduser()
            if not p.is_absolute():
                raise ValueError(
                    f"context dirs must be absolute or ~-anchored host paths: {entry!r}"
                )
        return value

    def context_mounts(self) -> list[tuple[Path, str]]:
        """(host path, container target) pairs for the read-only context mounts."""
        out: list[tuple[Path, str]] = []
        seen: set[str] = set()
        for entry in self.context:
            host = Path(entry).expanduser()
            base = host.name or "context"
            target = base
            n = 2
            while target in seen:
                target = f"{base}-{n}"
                n += 1
            seen.add(target)
            out.append((host, f"/context/{target}"))
        return out


class RemoteTransport(StrEnum):
    streamable_http = "streamable-http"
    sse = "sse"


class ServerSecret(StrictModel):
    """A docker secret the gateway makes available to a server as an env var.

    The daemon resolves the value from the OS keychain at container start, so
    neither the gateway process nor the agent ever holds it.
    """

    name: str
    env: str

    @field_validator("env")
    @classmethod
    def _validate_env(cls, value: str) -> str:
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", value):
            raise ValueError(f"not a valid environment variable name: {value!r}")
        return value


class RemoteServer(StrictModel):
    """An MCP server hosted on the internet, reached *through the gateway*.

    The agent never connects to it directly: the gateway container makes the
    outbound call, holds any credential, and still presents the agent with a
    single MCP endpoint. That keeps the agent's firewall unchanged and means a
    third-party MCP host is never something the sandbox has to trust.
    """

    url: str
    transport: RemoteTransport = RemoteTransport.streamable_http
    #: Header values may interpolate ``${ENV}`` from ``secrets`` below.
    headers: dict[str, str] = Field(default_factory=dict)
    secrets: list[ServerSecret] = Field(default_factory=list)
    description: str = ""

    @field_validator("url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError(
                f"remote MCP servers must be https: {value!r} — "
                "the gateway's connection to them crosses the public internet"
            )
        if " " in value:
            raise ValueError(f"not a valid URL: {value!r}")
        return value

    @model_validator(mode="after")
    def _headers_reference_declared_secrets(self) -> Self:
        declared = {s.env for s in self.secrets}
        used = set(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", " ".join(self.headers.values())))
        stray = sorted(used - declared)
        if stray:
            raise ValueError(
                f"header(s) interpolate undeclared secret env var(s): {', '.join(stray)} — "
                "add them under `secrets` so the gateway knows what to inject"
            )
        return self

    @property
    def host(self) -> str:
        rest = self.url.split("://", 1)[1]
        return rest.split("/", 1)[0].split("@")[-1].split(":")[0]


class RunConfig(StrictModel):
    """How ``abox run`` invokes ``claude`` inside the container."""

    permission_mode: PermissionMode = PermissionMode.default
    output: OutputFormat = OutputFormat.stream_json
    #: Let the agent load the MCP connectors attached to your claude.ai account
    #: (Gmail, Drive, Notion, Linear, …). Off by default because it is a second
    #: MCP path abox does not mediate: those tool calls do not appear in the
    #: gateway log and their capabilities are not declared in this manifest.
    #: Prefer `abox mcp add <name>` for anything the Docker catalog carries.
    connectors: bool = False
    #: Wall-clock ceiling for one headless run.
    timeout: int = Field(default=3600, ge=30, le=86_400)

    @property
    def single_mcp_endpoint(self) -> bool:
        """False once claude.ai connectors are allowed alongside the gateway."""
        return not self.connectors

    @property
    def requires_boundary_gate(self) -> bool:
        """``bypassPermissions`` is only allowed behind a proven sandbox."""
        return self.permission_mode is PermissionMode.bypass_permissions


class Manifest(StrictModel):
    """``agentbox.yaml`` — the project's declaration of its sandbox."""

    version: int = MANIFEST_VERSION
    project: Name
    profile: Name
    servers: list[str] = Field(default_factory=list)
    #: Internet-hosted MCP servers not in the Docker catalog, keyed by the name
    #: the gateway will expose them under.
    remote_servers: dict[str, RemoteServer] = Field(default_factory=dict)
    tools: dict[str, list[str]] = Field(default_factory=dict)
    toolchains: list[str] = Field(default_factory=list)
    mounts: MountsConfig = Field(default_factory=MountsConfig)
    egress: list[str] = Field(default_factory=list)
    #: Docker secrets handed to the *agent* as environment variables, as
    #: ``ENV_VAR: docker-secret-name``. This is the one place abox gives the
    #: agent a credential, so it is declared per project and reported by doctor.
    #:
    #: Values are passed as ``se://`` references that the Docker daemon resolves
    #: at container start: abox never reads them, and they never reach argv,
    #: runspec.json, or any file abox writes. They ARE visible to anyone who can
    #: run `docker inspect` on the agent container — unavoidable, since the
    #: agent itself must be able to read them.
    env_secrets: dict[str, str] = Field(default_factory=dict)
    #: Domains seen in the review queue and deliberately NOT allowed. Recorded so
    #: the queue keeps meaning "undecided" instead of accumulating history the
    #: operator has already ruled on.
    egress_ignored: list[str] = Field(default_factory=list)
    run: RunConfig = Field(default_factory=RunConfig)

    @field_validator("version")
    @classmethod
    def _validate_version(cls, value: int) -> int:
        if value != MANIFEST_VERSION:
            raise ValueError(
                f"unsupported manifest version {value} (this abox understands {MANIFEST_VERSION})"
            )
        return value

    @field_validator("project", "profile")
    @classmethod
    def _validate_names(cls, value: str) -> str:
        return _check_name(value, "name")

    @field_validator("servers")
    @classmethod
    def _validate_servers(cls, value: list[str]) -> list[str]:
        seen: set[str] = set()
        for name in value:
            _check_server_name(name)
            if name in seen:
                raise ValueError(f"duplicate server: {name!r}")
            seen.add(name)
        return value

    @field_validator("toolchains")
    @classmethod
    def _validate_toolchains(cls, value: list[str]) -> list[str]:
        unknown = [t for t in value if t not in TOOLCHAINS]
        if unknown:
            known = ", ".join(sorted(TOOLCHAINS))
            raise ValueError(f"unknown toolchain(s): {', '.join(unknown)} (known: {known})")
        return value

    @field_validator("egress", "egress_ignored")
    @classmethod
    def _validate_egress(cls, value: list[str]) -> list[str]:
        out: list[str] = []
        for host in value:
            normalized = _check_host(host)
            if normalized not in out:
                out.append(normalized)
        return out

    @model_validator(mode="after")
    def _tools_reference_declared_servers(self) -> Self:
        stray = sorted(set(self.tools) - set(self.all_servers))
        if stray:
            raise ValueError(
                f"tools filter references undeclared server(s): {', '.join(stray)} — "
                "add them to `servers` or drop the filter"
            )
        return self

    @field_validator("env_secrets")
    @classmethod
    def _validate_env_secrets(cls, value: dict[str, str]) -> dict[str, str]:
        for env, secret in value.items():
            if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", env):
                raise ValueError(f"not a valid environment variable name: {env!r}")
            if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", secret):
                raise ValueError(f"invalid docker secret name: {secret!r}")
            if env in RESERVED_AGENT_ENV:
                raise ValueError(
                    f"{env} is set by abox itself and cannot be overridden by a secret"
                )
        return value

    @model_validator(mode="after")
    def _ignored_are_not_also_allowed(self) -> Self:
        both = sorted(set(self.egress) & set(self.egress_ignored))
        if both:
            raise ValueError(
                f"{', '.join(both)} appear(s) in both egress and egress_ignored — "
                "allow it or ignore it, not both"
            )
        return self

    @model_validator(mode="after")
    def _remote_names_do_not_collide(self) -> Self:
        for name in self.remote_servers:
            _check_server_name(name, "remote server name")
        clash = sorted(set(self.remote_servers) & set(self.servers))
        if clash:
            raise ValueError(
                f"remote_servers and servers both declare: {', '.join(clash)} — "
                "the gateway would see two servers under one name"
            )
        return self

    @property
    def all_servers(self) -> list[str]:
        """Catalog servers plus locally declared remote ones."""
        return [*self.servers, *self.remote_servers]

    # -- serialization ----------------------------------------------------

    def to_yaml(self) -> str:
        body = self.model_dump(mode="json", exclude_defaults=False)
        header = (
            "# agentbox.yaml — generated by abox; safe to hand-edit.\n"
            "# `abox doctor` validates this file against the same schema that wrote it.\n"
        )
        return header + yaml.safe_dump(body, sort_keys=False, default_flow_style=False)

    def write(self, workspace: Path) -> Path:
        target = paths.manifest_path(workspace)
        target.write_text(self.to_yaml(), encoding="utf-8")
        return target

    @classmethod
    def load(cls, workspace: Path) -> Manifest:
        target = paths.manifest_path(workspace)
        if not target.is_file():
            raise ManifestNotFoundError(str(target))
        return cls.parse_yaml(target.read_text(encoding="utf-8"), source=str(target))

    @classmethod
    def parse_yaml(cls, text: str, *, source: str = "<manifest>") -> Manifest:
        try:
            data = yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{source} is not valid YAML: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError(f"{source} must be a YAML mapping")
        try:
            return cls.model_validate(data)
        except ValidationError as exc:
            raise ConfigError(f"{source} is invalid:\n{_format_errors(exc)}") from exc


class RtkConfig(StrictModel):
    """`rtk` — a CLI proxy that filters verbose command output before the model
    sees it. Off by default: it installs a ``PreToolUse`` hook, which means every
    Bash command the agent runs is rewritten by another program. That is a
    reasonable trade for the operator's own tool, and a bad thing to do silently.
    """

    enabled: bool = False
    version: str = "0.43.0"
    repo: str = "rtk-ai/rtk"


class EgressProxyConfig(StrictModel):
    """SNI-aware egress filtering.

    With this on, the agent's firewall stops allowlisting addresses and permits
    exactly one destination — the proxy — which decides by the server name in
    the TLS ClientHello. That is the difference between an address-level and a
    domain-level allowlist, and it is the only way to stop a request reaching a
    different host at an allowed IP.
    """

    enabled: bool = False
    image: str = "nginx:alpine"
    port: int = Field(default=8443, ge=1024, le=65535)
    #: Idle timeout for a proxied connection.
    timeout: int = Field(default=300, ge=10, le=86_400)


class ProfileConfig(StrictModel):
    """One gateway profile: a named set of servers reachable on a fixed port."""

    port: int = Field(default=8811, ge=1024, le=65535)
    description: str = ""


class Defaults(StrictModel):
    mask: list[str] = Field(default_factory=lambda: [".env*", ".git/hooks"])
    egress_mandatory: list[str] = Field(default_factory=lambda: list(BASE_MANDATORY_EGRESS))

    @field_validator("egress_mandatory")
    @classmethod
    def _validate_egress(cls, value: list[str]) -> list[str]:
        return [_check_host(h) for h in value]


#: The tag the shipped gateway digest was resolved from. `abox gateway update`
#: re-resolves this; doctor names it when the running gateway has drifted.
GATEWAY_IMAGE_TAG = "docker/mcp-gateway:v2"

#: Digest-pinned by default. The gateway is the most privileged container abox
#: runs — it is the one that mounts ``/var/run/docker.sock`` — so leaving it on
#: a mutable tag while every MCP server image is pinned was an inconsistency,
#: not a convenience. Re-resolve with `abox gateway update`.
DEFAULT_GATEWAY_IMAGE = (
    "docker/mcp-gateway@sha256:"
    "54dd518ee51b5c4641b02ddd4790b88cc0dafa59d76b6d07bc441d896a23bbea"
)


class GlobalConfig(StrictModel):
    """``~/.config/abox/config.yaml``."""

    network: str = "abox-net"
    gateway_image: str = DEFAULT_GATEWAY_IMAGE
    #: Base image for the agent container.
    agent_base_image: str = "mcr.microsoft.com/devcontainers/base:ubuntu"
    #: Claude Code release to bake in: "latest" or an exact x.y.z to pin.
    claude_version: str = "latest"
    #: Toolchain versions fetched from upstream tarballs at build time.
    toolchain_versions: dict[str, str] = Field(
        default_factory=lambda: {"go": "1.24.5", "node": "22.14.0"}
    )
    #: Unprivileged user inside the agent container.
    remote_user: str = "vscode"
    #: Optional output-filtering proxy inside the agent container.
    rtk: RtkConfig = Field(default_factory=RtkConfig)
    #: SNI-aware egress proxy; makes the allowlist domain-level.
    egress_proxy: EgressProxyConfig = Field(default_factory=EgressProxyConfig)
    #: Destination ports opened to allowlisted addresses. 443 only by default:
    #: plaintext HTTP is rarely needed and is a downgrade path.
    egress_ports: list[int] = Field(default_factory=lambda: [443])
    #: Resolve only allowlisted names. Arbitrary resolution is a covert channel
    #: that survives default-deny egress, because the query name carries data.
    scoped_dns: bool = True
    #: Environment that turns off the traffic abox deliberately does not allow,
    #: so the agent stops retrying blocked hosts. Override to re-enable any of
    #: it — and add the matching domain to `defaults.egress_mandatory` if you do.
    agent_env: dict[str, str] = Field(
        default_factory=lambda: {
            "DISABLE_AUTOUPDATER": "1",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
        }
    )
    profiles: dict[str, ProfileConfig] = Field(
        default_factory=lambda: {"default": ProfileConfig()}
    )
    defaults: Defaults = Field(default_factory=Defaults)

    @field_validator("network")
    @classmethod
    def _validate_network(cls, value: str) -> str:
        return _check_name(value, "network name")

    @model_validator(mode="after")
    def _profiles_have_unique_ports(self) -> Self:
        for name in self.profiles:
            _check_name(name, "profile name")
        ports: dict[int, str] = {}
        for name, profile in self.profiles.items():
            if profile.port in ports:
                raise ValueError(
                    f"profiles {ports[profile.port]!r} and {name!r} both claim port {profile.port}"
                )
            ports[profile.port] = name
        return self

    @property
    def gateway_image_pinned(self) -> bool:
        return bool(_DIGEST_RE.match(self.gateway_image))

    def profile(self, name: str) -> ProfileConfig:
        try:
            return self.profiles[name]
        except KeyError:
            known = ", ".join(sorted(self.profiles)) or "(none)"
            raise ConfigError(
                f"unknown profile {name!r}",
                hint=f"profiles defined in {paths.global_config_path()}: {known}",
            ) from None

    def to_yaml(self) -> str:
        header = "# abox global config\n"
        return header + yaml.safe_dump(
            self.model_dump(mode="json"), sort_keys=False, default_flow_style=False
        )

    @classmethod
    def load(cls, *, create: bool = True) -> GlobalConfig:
        target = paths.global_config_path()
        if not target.is_file():
            if not create:
                raise ConfigError(
                    f"no global config at {target}",
                    hint="run `abox init` (it scaffolds one) or create it by hand",
                )
            cfg = cls()
            cfg.save()
            return cfg
        try:
            data = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{target} is not valid YAML: {exc}") from exc
        try:
            return cls.model_validate(data)
        except ValidationError as exc:
            raise ConfigError(f"{target} is invalid:\n{_format_errors(exc)}") from exc

    def save(self) -> Path:
        target = paths.global_config_path()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.parent.chmod(0o700)
        target.write_text(self.to_yaml(), encoding="utf-8")
        target.chmod(0o600)
        return target


class SecretSource(StrEnum):
    """Where a secret's value comes from. All of them are optional."""

    op = "op"  # 1Password CLI reference
    file = "file"  # a mode-checked file on the host
    env = "env"  # a host environment variable
    prompt = "prompt"  # typed at the terminal, never stored by abox
    docker = "docker"  # already in the Docker secret store; abox only verifies it


class SecretMapping(StrictModel):
    """One source -> one docker secret name.

    Exactly one source field may be set. ``source: docker`` means "somebody else
    put this in the store" — abox then checks presence and stays out of the way.
    """

    secret: str
    op: str | None = None
    file: str | None = None
    env: str | None = None
    source: SecretSource | None = None
    description: str = ""

    @field_validator("op")
    @classmethod
    def _validate_op_ref(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value.startswith("op://"):
            raise ValueError(f"not a 1Password secret reference: {value!r} (expected op://…)")
        if len(value.split("/")) < 5:
            raise ValueError(f"incomplete op reference: {value!r} (expected op://vault/item/field)")
        return value

    @field_validator("env")
    @classmethod
    def _validate_env(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", value):
            raise ValueError(f"not a valid environment variable name: {value!r}")
        return value

    @field_validator("secret")
    @classmethod
    def _validate_secret_name(cls, value: str) -> str:
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", value):
            raise ValueError(f"invalid docker secret name: {value!r}")
        return value

    @model_validator(mode="after")
    def _exactly_one_source(self) -> Self:
        set_fields = [name for name in ("op", "file", "env") if getattr(self, name)]
        if len(set_fields) > 1:
            raise ValueError(
                f"secret {self.secret!r} declares more than one source: {', '.join(set_fields)}"
            )
        explicit = self.source in (SecretSource.op, SecretSource.file, SecretSource.env)
        if explicit and (not set_fields or set_fields[0] != self.source.value):
            raise ValueError(
                f"secret {self.secret!r} declares source: {self.source.value} "
                f"but no {self.source.value}: field"
            )
        if not set_fields and self.source is None:
            raise ValueError(
                f"secret {self.secret!r} has no source — set one of op/file/env, "
                "or source: docker (already in the store) / source: prompt (type it in)"
            )
        return self

    @property
    def kind(self) -> SecretSource:
        if self.source is not None:
            return self.source
        for name in ("op", "file", "env"):
            if getattr(self, name):
                return SecretSource(name)
        return SecretSource.docker  # pragma: no cover - guarded by the validator

    @property
    def reference(self) -> str:
        """A displayable pointer to the source. Never the value itself."""
        match self.kind:
            case SecretSource.op:
                return self.op or ""
            case SecretSource.file:
                return self.file or ""
            case SecretSource.env:
                return f"${self.env}"
            case SecretSource.prompt:
                return "(typed at the terminal)"
            case _:
                return "(managed outside abox)"

    @property
    def readable(self) -> bool:
        """Can abox obtain the value non-interactively? Drives drift detection."""
        return self.kind in (SecretSource.op, SecretSource.file, SecretSource.env)


class SecretsConfig(StrictModel):
    """``~/.config/abox/secrets.yaml`` — references only, never values."""

    mappings: list[SecretMapping] = Field(default_factory=list)

    @property
    def sources(self) -> set[SecretSource]:
        return {m.kind for m in self.mappings}

    def needs_op(self) -> bool:
        return SecretSource.op in self.sources

    @model_validator(mode="after")
    def _unique_targets(self) -> Self:
        seen: set[str] = set()
        for mapping in self.mappings:
            if mapping.secret in seen:
                raise ValueError(f"duplicate secret target: {mapping.secret!r}")
            seen.add(mapping.secret)
        return self

    @classmethod
    def load(cls) -> SecretsConfig:
        target = paths.secrets_config_path()
        if not target.is_file():
            return cls()
        try:
            data = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{target} is not valid YAML: {exc}") from exc
        try:
            return cls.model_validate(data)
        except ValidationError as exc:
            raise ConfigError(f"{target} is invalid:\n{_format_errors(exc)}") from exc


class CustomServer(StrictModel):
    """An MCP server image outside the Docker catalog, declared by the operator.

    abox renders these into a catalog it mounts into the gateway, which is how a
    self-hosted image — and a secret name of your own choosing — reaches the
    agent without going through the public Docker catalog.
    """

    image: str
    #: Require ``image`` to be digest-pinned — the default and the safe choice.
    #: Set ``pin: false`` to run a local image you built yourself (e.g.
    #: ``serena:local``) and never pushed to a registry: abox then trusts it on
    #: your say-so and will not try to pull it. This governs only abox's own
    #: digest requirement — the Docker MCP gateway signature-verifies images in
    #: the ``docker.io/mcp/*`` namespace alone, so an out-of-namespace image runs
    #: unverified either way.
    pin: bool = True
    secrets: list[ServerSecret] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=lambda: ["*"])
    description: str = ""
    #: Non-secret environment for the server container.
    env: dict[str, str] = Field(default_factory=dict)
    #: Arguments appended to the image entrypoint.
    command: list[str] = Field(default_factory=list)
    #: Docker volume specs for the server's own container (``name:/path``).
    volumes: list[str] = Field(default_factory=list)

    def catalog_entry(self, name: str) -> dict[str, Any]:
        """This server as a Docker MCP v3 catalog entry.

        The gateway only knows servers that appear in a catalog it can read, so
        this is what makes a self-hosted image reachable at all.
        """
        entry: dict[str, Any] = {
            "description": self.description or f"custom MCP server {name}",
            "title": name,
            "type": "server",
            "image": self.image,
        }
        if self.secrets:
            entry["secrets"] = [{"name": s.name, "env": s.env} for s in self.secrets]
        if self.env:
            entry["env"] = [{"name": k, "value": v} for k, v in sorted(self.env.items())]
        if self.command:
            entry["command"] = list(self.command)
        if self.volumes:
            entry["volumes"] = list(self.volumes)
        if not self.all_tools:
            entry["tools"] = [{"name": tool} for tool in self.tools]
        return entry

    @field_validator("secrets", mode="before")
    @classmethod
    def _accept_bare_names(cls, value: object) -> object:
        """``secrets: [some.token]`` is the obvious way to write it.

        Derive the env var from the name so the short form keeps working:
        ``some.token`` -> ``SOME_TOKEN``.
        """
        if not isinstance(value, list):
            return value
        out = []
        for entry in value:
            if isinstance(entry, str):
                env = re.sub(r"[^A-Za-z0-9]+", "_", entry).upper().strip("_")
                out.append({"name": entry, "env": env})
            else:
                out.append(entry)
        return out

    @model_validator(mode="after")
    def _require_digest_when_pinned(self) -> CustomServer:
        if self.pin and not _DIGEST_RE.match(self.image):
            raise ValueError(
                f"custom server images must be digest-pinned: {self.image!r} "
                "(expected registry/name@sha256:<64 hex>) — or set `pin: false` "
                "to trust a local image you built yourself"
            )
        return self

    @property
    def all_tools(self) -> bool:
        return self.tools == ["*"] or not self.tools


class CustomServers(StrictModel):
    """``~/.config/abox/custom-servers.yaml`` — a bare mapping of name -> server."""

    servers: dict[str, CustomServer] = Field(default_factory=dict)

    @classmethod
    def load(cls) -> CustomServers:
        target = paths.custom_servers_path()
        if not target.is_file():
            return cls()
        try:
            data = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{target} is not valid YAML: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError(f"{target} must be a YAML mapping of server-name -> server")
        # The file is a bare mapping; wrap it for the model.
        payload = data if set(data) == {"servers"} else {"servers": data}
        try:
            return cls.model_validate(payload)
        except ValidationError as exc:
            raise ConfigError(f"{target} is invalid:\n{_format_errors(exc)}") from exc

    def __contains__(self, name: object) -> bool:
        return name in self.servers

    def get(self, name: str) -> CustomServer | None:
        return self.servers.get(name)


def format_errors(exc: ValidationError) -> str:
    """Render pydantic's errors as the short, located list abox shows users."""
    return _format_errors(exc)


def _format_errors(exc: ValidationError) -> str:
    lines: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"]) or "(root)"
        lines.append(f"  {loc}: {err['msg']}")
    return "\n".join(lines)


def merged_masks(manifest: Manifest, config: GlobalConfig) -> list[str]:
    """Global default masks plus project masks, order-stable and de-duplicated."""
    out: list[str] = []
    for glob in (*config.defaults.mask, *manifest.mounts.mask):
        if glob not in out:
            out.append(glob)
    return out


def merged_egress(
    manifest: Manifest, config: GlobalConfig, *, extra: list[str] | None = None
) -> list[str]:
    """Project egress, plus mandatory egress, plus caller-injected entries."""
    out: list[str] = []
    for host in (*manifest.egress, *config.defaults.egress_mandatory, *(extra or [])):
        h = host.strip().lower()
        if h and h not in out:
            out.append(h)
    return out


def effective_allowlist(manifest: Manifest, config: GlobalConfig) -> list[str]:
    """Everything the firewall will actually route to, including the gateway.

    The gateway is reached by container name rather than a public domain, so it
    never appears in ``egress`` — but the agent does resolve it, and a review
    queue that flagged it every run would be noise.
    """
    from . import paths as _paths

    return merged_egress(
        manifest, config, extra=[_paths.gateway_container(manifest.profile)]
    )


#: Historical name; remote and image servers share one secret shape.
RemoteSecret = ServerSecret
