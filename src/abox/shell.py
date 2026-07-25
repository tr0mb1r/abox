"""Subprocess plumbing.

Every external command abox runs goes through :func:`run` or :func:`run_piped`.
Two reasons:

1. **Testability** — tests install a fake runner via :func:`set_runner` and assert
   on the recorded argv without a Docker daemon anywhere near them.
2. **Secret hygiene** — :func:`run_piped` is the only way to move a credential
   between two processes, and it moves it over stdin. Nothing that carries a
   secret value is ever allowed to become an argv element (argv is world-readable
   in ``ps`` output on macOS and Linux alike).
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .errors import HostToolError

DEFAULT_TIMEOUT = 120


#: Docker ends most failures with this; the useful line is the one before it.
_NOISE_SUFFIXES = ("for more information", "See 'docker", "Usage:")


def first_useful_line(text: str) -> str:
    """The first line of an error worth showing a human.

    Docker puts its diagnosis first and a generic "Run 'docker run --help'"
    trailer last, so taking the last line — the obvious thing — reliably throws
    away the only part that says what went wrong.
    """
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    for line in lines:
        if not any(noise in line for noise in _NOISE_SUFFIXES):
            return line
    return lines[0] if lines else ""


@dataclass(frozen=True)
class Result:
    """Outcome of one external command."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def check(self, what: str) -> Result:
        from .errors import AboxError

        if self.ok:
            return self
        detail = (self.stderr or self.stdout).strip().splitlines()
        tail = detail[-1] if detail else f"exit code {self.returncode}"
        raise AboxError(f"{what} failed: {tail}", hint=f"command: {' '.join(self.argv)}")

    @property
    def lines(self) -> list[str]:
        return [ln for ln in self.stdout.splitlines() if ln.strip()]


Runner = Callable[[Sequence[str], "RunOptions"], Result]


@dataclass
class RunOptions:
    """Everything about an invocation except the argv itself."""

    cwd: Path | None = None
    env: dict[str, str] | None = None
    timeout: int = DEFAULT_TIMEOUT
    stdin_data: str | None = None
    stream: bool = False
    #: Called with each stdout line when ``stream`` is set.
    on_line: Callable[[str], None] | None = None
    #: Extra env merged on top of ``os.environ`` (ignored when ``env`` is set).
    env_extra: dict[str, str] = field(default_factory=dict)


def _real_runner(argv: Sequence[str], opts: RunOptions) -> Result:
    env = opts.env
    if env is None:
        env = {**os.environ, **opts.env_extra}
    if opts.stream:
        return _stream(argv, opts, env)
    proc = subprocess.run(
        list(argv),
        cwd=str(opts.cwd) if opts.cwd else None,
        env=env,
        input=opts.stdin_data,
        capture_output=True,
        text=True,
        timeout=opts.timeout,
        check=False,
    )
    return Result(tuple(argv), proc.returncode, proc.stdout, proc.stderr)


def _stream(argv: Sequence[str], opts: RunOptions, env: dict[str, str]) -> Result:
    """Run a long-lived command, forwarding stdout lines as they arrive."""
    chunks: list[str] = []
    with subprocess.Popen(
        list(argv),
        cwd=str(opts.cwd) if opts.cwd else None,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    ) as proc:
        assert proc.stdout is not None  # noqa: S101 - Popen contract with PIPE
        for line in proc.stdout:
            chunks.append(line)
            if opts.on_line:
                opts.on_line(line.rstrip("\n"))
        proc.wait(timeout=opts.timeout)
        stderr = proc.stderr.read() if proc.stderr else ""
    return Result(tuple(argv), proc.returncode, "".join(chunks), stderr)


_runner: Runner = _real_runner


def set_runner(runner: Runner) -> Runner:
    """Install a runner (tests). Returns the previous one."""
    global _runner
    previous = _runner
    _runner = runner
    return previous


@contextlib.contextmanager
def using_runner(runner: Runner) -> Iterator[None]:
    previous = set_runner(runner)
    try:
        yield
    finally:
        set_runner(previous)


def run(argv: Sequence[str], **kwargs: object) -> Result:
    """Run a command and capture its output."""
    return _runner(list(argv), RunOptions(**kwargs))  # type: ignore[arg-type]


def run_piped(argv: Sequence[str], stdin_data: str, **kwargs: object) -> Result:
    """Run a command feeding ``stdin_data`` on stdin.

    The only sanctioned path for a secret value. Never log ``stdin_data``, never
    echo it back, never let it reach argv.
    """
    return _runner(list(argv), RunOptions(stdin_data=stdin_data, **kwargs))  # type: ignore[arg-type]


def which(tool: str) -> str | None:
    return shutil.which(tool)


def require(tool: str, *, hint: str | None = None) -> str:
    path = which(tool)
    if path is None:
        raise HostToolError(tool, hint=hint)
    return path


INSTALL_HINTS = {
    "docker": "install Docker Desktop >= 4.48 and enable the MCP Toolkit",
    "op": "install the 1Password CLI: brew install 1password-cli, then sign in",
    "claude": "install Claude Code on the host (only needed for host-side checks)",
}


def require_tool(tool: str) -> str:
    return require(tool, hint=INSTALL_HINTS.get(tool))
