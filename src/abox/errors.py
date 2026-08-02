"""Error hierarchy for abox.

Every failure path that a user can plausibly hit raises an ``AboxError`` subclass
carrying a human-readable ``hint``. ``cli.py`` catches ``AboxError`` at the top
level and renders it without a traceback; anything else is a bug and keeps its
traceback.
"""

from __future__ import annotations


class AboxError(Exception):
    """Base class for expected, user-facing failures."""

    exit_code = 1

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint


class ConfigError(AboxError):
    """Global config or project manifest is missing, malformed, or invalid."""


class ManifestNotFoundError(ConfigError):
    """No ``agentbox.yaml`` in the project directory."""

    def __init__(self, path: str) -> None:
        super().__init__(
            f"no agentbox.yaml found at {path}",
            hint="run `abox init` in the project directory first",
        )


class HostToolError(AboxError):
    """A required host binary is missing or the wrong version."""

    def __init__(self, tool: str, *, hint: str | None = None) -> None:
        super().__init__(f"required host tool not found: {tool}", hint=hint)
        self.tool = tool


class DockerError(AboxError):
    """A ``docker`` invocation failed."""


class CommandTimeoutError(AboxError):
    """An external command exceeded its timeout and was killed.

    ``subprocess.TimeoutExpired`` is not an ``AboxError``, so before this class
    existed a timeout reached the user as a traceback — on the rare paths where
    it could fire at all. The streaming path, which is every ``docker build``,
    ``docker run`` and ``docker exec``, could not time out in the first place.
    """

    def __init__(self, argv: list[str], timeout: float) -> None:
        # No config pointer: `run.timeout` governs exactly one caller (the agent
        # exec), and every other timeout here is a constant the operator cannot
        # raise — so naming it sends most readers to edit a setting that has no
        # bearing on the command that actually failed.
        super().__init__(
            f"`{' '.join(argv[:3])}` exceeded its {timeout:.0f}s timeout and was killed",
            hint="the process group was killed; check whether Docker or the "
            "container is wedged, and `abox doctor` for the daemon",
        )
        self.argv = argv
        self.timeout = timeout


class GatewayError(AboxError):
    """Gateway container is missing, unhealthy, or refused to start."""


class SecretsError(AboxError):
    """1Password read or docker secret write failed."""


class BoundaryError(AboxError):
    """A security boundary check failed; abox refuses to proceed.

    This is the one error class that must never be downgraded to a warning:
    it is raised when the sandbox would run without the isolation the manifest
    claims (e.g. ``bypassPermissions`` with no firewall).
    """

    exit_code = 3


class RenderError(AboxError):
    """Template rendering or artifact drift detection failed."""
