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
import signal
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


#: How long a signalled process group gets to die before we escalate, and how
#: long a pipe-reader thread gets to finish once nothing should be writing. Both
#: are bounded: a process that escapes the group can hold a pipe open forever,
#: and truncated output beats a wedged CLI.
_TERM_GRACE = 5
_PUMP_JOIN = 5


def _pump(
    pipe: IO[str],
    sink: list[str],
    on_line: Callable[[str], None] | None,
    failure: list[BaseException],
) -> None:
    """Drain one pipe to EOF, whatever the caller's callback does.

    Two separate guards, because they protect against opposite things and
    collapsing them was a defect in its own right:

    * the read can fail because the pipe was closed under us while the child
      was being killed — expected, and nothing to report;
    * the callback can raise for reasons that have nothing to do with the pipe.
      ``cli._print_stream_event`` hands unescaped agent text to Rich, so an
      assistant message mentioning ``[/etc/hosts]`` raises ``MarkupError``, and
      ``abox up | head`` turns a ``BrokenPipeError`` into ``SystemExit``.

    A callback failure must never stop the drain. ``on_line`` used to run on the
    caller's thread, where it surfaced in milliseconds; on a pump thread, a
    stopped drain means the child blocks on a full 64 KiB pipe and the whole run
    wedges until its deadline — up to an hour — reported as a timeout rather
    than as the error it is. So the exception is recorded, the callback is
    dropped for the rest of the stream, and the pipe keeps draining.
    """
    try:
        for line in pipe:
            sink.append(line)
            if on_line is not None and not failure:
                try:
                    on_line(line.rstrip("\n"))
                except BaseException as exc:  # including SystemExit — the caller's to raise
                    failure.append(exc)
    except (ValueError, OSError):
        # The pipe was closed under us while the child was being killed.
        pass


def _signal_group(proc: subprocess.Popen[str], sig: int) -> None:
    """Signal the child's whole process group, falling back to the child alone.

    Killing only the direct child is not enough. ``sh -c 'sleep 20'`` *forks* on
    Linux where it *execs* on macOS, so the shell dies on SIGTERM and the
    grandchild lives on holding the inherited stdout and stderr — which means
    the pipes never reach EOF and the reader threads never finish. The child is
    started in its own session so there is a group to signal here.
    """
    with contextlib.suppress(OSError):
        os.killpg(os.getpgid(proc.pid), sig)
        return
    with contextlib.suppress(OSError):
        proc.send_signal(sig)


def _terminate(proc: subprocess.Popen[str]) -> None:
    """SIGTERM the group, then SIGKILL if anything is still there, then reap."""
    _signal_group(proc, signal.SIGTERM)
    try:
        proc.wait(timeout=_TERM_GRACE)
        return
    except subprocess.TimeoutExpired:
        pass
    _signal_group(proc, signal.SIGKILL)
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=_TERM_GRACE)


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
    proc = subprocess.Popen(
        list(argv),
        cwd=str(opts.cwd) if opts.cwd else None,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        # Its own process group, so _signal_group can reach the grandchildren
        # that inherited these pipes. Ctrl-C no longer reaches the child through
        # the terminal as a side effect, so it is forwarded explicitly below.
        start_new_session=True,
    )
    assert proc.stdout is not None and proc.stderr is not None  # noqa: S101
    sink_failure: list[BaseException] = []
    pumps = [
        threading.Thread(
            target=_pump, args=(proc.stdout, chunks, opts.on_line, sink_failure), daemon=True
        ),
        threading.Thread(target=_pump, args=(proc.stderr, err_chunks, None, []), daemon=True),
    ]
    for pump in pumps:
        pump.start()

    timed_out = False
    try:
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate(proc)
        except BaseException:
            # Ctrl-C, or anything else unwinding this thread. The child is in its
            # own group and would otherwise be orphaned still running.
            _terminate(proc)
            raise
    finally:
        # Deliberately not `with subprocess.Popen(...)`. Its __exit__ closes the
        # pipes and then calls wait() with no timeout, and closing a pipe blocks
        # on an in-flight read in the pump thread — so a grandchild holding the
        # pipe open turned into an unbounded wait inside the cleanup that was
        # supposed to bound it. Everything here has a deadline.
        for pump in pumps:
            pump.join(_PUMP_JOIN)
        for pipe in (proc.stdout, proc.stderr):
            with contextlib.suppress(OSError, ValueError):
                pipe.close()

    # Before the timeout: a callback that raised is the *cause* of any stall it
    # produced, and reporting the symptom instead would send the reader to look
    # at Docker. This is also where it surfaced before on_line moved off this
    # thread, so callers see the same exception they always did.
    if sink_failure:
        raise sink_failure[0]
    if timed_out:
        raise subprocess.TimeoutExpired(
            list(argv), timeout or 0, output="".join(chunks), stderr="".join(err_chunks)
        )
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
