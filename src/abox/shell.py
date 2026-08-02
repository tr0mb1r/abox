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
import threading
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

from .errors import CommandTimeoutError, HostToolError

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


#: How long a killed child gets to die before we stop waiting for it, and how
#: long a pipe-reader thread gets to finish once the child is gone. Both are
#: bounded because a grandchild can inherit the pipe and hold it open forever.
_REAP_GRACE = 10
_PUMP_JOIN = 5


def _pump(pipe: IO[str], sink: list[str], on_line: Callable[[str], None] | None) -> None:
    """Drain one pipe to EOF. Never raises into the caller's thread."""
    try:
        for line in pipe:
            sink.append(line)
            if on_line:
                on_line(line.rstrip("\n"))
    except (ValueError, OSError):
        # The pipe was closed under us while the child was being killed.
        pass


def _terminate(proc: subprocess.Popen[str]) -> None:
    """SIGTERM, then SIGKILL if it is still there, then reap it."""
    with contextlib.suppress(OSError):
        proc.terminate()
    try:
        proc.wait(timeout=_REAP_GRACE)
        return
    except subprocess.TimeoutExpired:
        pass
    with contextlib.suppress(OSError):
        proc.kill()
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=_REAP_GRACE)


def _stream(argv: Sequence[str], opts: RunOptions, env: dict[str, str]) -> Result:
    """Run a long-lived command, forwarding stdout lines as they arrive.

    Both pipes are drained on their own threads while this one waits on the
    child, which is what makes the timeout real. The obvious shape —
    ``for line in proc.stdout`` then ``proc.wait(timeout=…)`` — is wrong twice
    over, and streaming is the default path for every ``docker build``,
    ``docker run`` and ``docker exec`` abox makes:

    * the timeout was unreachable. A child that stalls without printing blocks
      in the iterator forever and never arrives at ``wait``. Even on arrival,
      ``TimeoutExpired`` propagating out of the ``with`` sent ``Popen.__exit__``
      into ``wait()`` with no timeout at all, and nothing ever killed the child.
    * stderr has its own ~64 KiB pipe buffer, and it was read only after stdout
      hit EOF. A child that fills it blocks writing while we block reading
      stdout — a deadlock with no timeout to break it. ``docker build`` puts the
      whole BuildKit progress stream on stderr, so this was one long build away.
    """
    chunks: list[str] = []
    err_chunks: list[str] = []
    timeout = opts.timeout or None
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
        assert proc.stdout is not None and proc.stderr is not None  # noqa: S101
        pumps = [
            threading.Thread(
                target=_pump, args=(proc.stdout, chunks, opts.on_line), daemon=True
            ),
            threading.Thread(target=_pump, args=(proc.stderr, err_chunks, None), daemon=True),
        ]
        for pump in pumps:
            pump.start()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _terminate(proc)
            for pump in pumps:
                pump.join(_PUMP_JOIN)
            raise subprocess.TimeoutExpired(
                list(argv), timeout or 0, output="".join(chunks), stderr="".join(err_chunks)
            ) from None
        # The child is gone; the pumps are draining what is left in the buffers.
        # Bounded, because a grandchild holding the pipe would otherwise hang us
        # here instead — truncated output beats a wedged CLI.
        for pump in pumps:
            pump.join(_PUMP_JOIN)
    return Result(tuple(argv), proc.returncode, "".join(chunks), "".join(err_chunks))


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


def _invoke(argv: Sequence[str], opts: RunOptions) -> Result:
    """Call the installed runner, turning a timeout into a user-facing error.

    Both real paths can raise ``TimeoutExpired`` — ``subprocess.run`` does it
    itself, and ``_stream`` now does it after killing the child — and nothing in
    abox catches it, so it reached the CLI as a traceback. A timeout is an
    expected failure, not a bug.
    """
    try:
        return _runner(list(argv), opts)
    except subprocess.TimeoutExpired as exc:
        raise CommandTimeoutError(list(argv), float(exc.timeout or opts.timeout)) from exc


def run(argv: Sequence[str], **kwargs: object) -> Result:
    """Run a command and capture its output."""
    return _invoke(list(argv), RunOptions(**kwargs))  # type: ignore[arg-type]


def run_piped(argv: Sequence[str], stdin_data: str, **kwargs: object) -> Result:
    """Run a command feeding ``stdin_data`` on stdin.

    The only sanctioned path for a secret value. Never log ``stdin_data``, never
    echo it back, never let it reach argv.
    """
    return _invoke(list(argv), RunOptions(stdin_data=stdin_data, **kwargs))  # type: ignore[arg-type]


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
