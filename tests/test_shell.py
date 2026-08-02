"""The subprocess plumbing itself, against real children.

Every other test in the suite installs a FakeRunner, which is the right trade for
asserting argv without a Docker daemon — and it means `_stream` had never once
been executed by the suite. These tests run real `/bin/sh` children, because the
two defects here are a timeout that could not fire and a deadlock between two
pipes, and neither is visible to a fake.

Each one is bounded by a watchdog thread: a regression here hangs forever, and a
test that hangs CI is worse than a test that fails it.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

import pytest

from abox import shell
from abox.errors import CommandTimeoutError

WATCHDOG_S = 25


def bounded(fn: Callable[[], Any], seconds: int = WATCHDOG_S) -> Any:
    """Run ``fn`` on a daemon thread so a deadlock fails instead of wedging."""
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # re-raised on the main thread
            box["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(seconds)
    assert not thread.is_alive(), f"shell.run did not return within {seconds}s — deadlock"
    if "error" in box:
        raise box["error"]
    return box["value"]


@pytest.fixture(autouse=True)
def real_runner():
    """These tests need the real runner, not the suite-wide fake."""
    previous = shell.set_runner(shell._real_runner)
    try:
        yield
    finally:
        shell.set_runner(previous)


def test_streaming_forwards_lines_and_captures_both_pipes() -> None:
    lines: list[str] = []
    result = bounded(
        lambda: shell.run(
            ["/bin/sh", "-c", "echo one; echo two; echo problem >&2"],
            timeout=20,
            stream=True,
            on_line=lines.append,
        )
    )
    assert result.ok
    assert lines == ["one", "two"]
    assert "problem" in result.stderr


def test_a_stalled_child_hits_its_timeout_instead_of_blocking_forever() -> None:
    """The timeout was decorative: `for line in proc.stdout` blocks until the
    child exits, so `proc.wait(timeout=…)` was only ever reached once waiting was
    already over. A child that stalls without printing never got there at all.
    """
    started = time.monotonic()
    with pytest.raises(CommandTimeoutError):
        bounded(
            lambda: shell.run(
                ["/bin/sh", "-c", "sleep 20"],
                timeout=1,
                stream=True,
                on_line=lambda _line: None,
            )
        )
    elapsed = time.monotonic() - started
    assert elapsed < 15, f"waited {elapsed:.0f}s — the deadline did not drive the wait"


def test_the_timed_out_child_is_killed_not_left_running() -> None:
    """`TimeoutExpired` used to propagate out of the `with`, sending
    `Popen.__exit__` into `wait()` with no timeout — and nothing ever killed the
    child, so the CLI hung there instead."""
    import subprocess

    marker = "abox-timeout-probe-marker"
    with pytest.raises(CommandTimeoutError):
        bounded(
            lambda: shell.run(
                ["/bin/sh", "-c", f"# {marker}\nsleep 20"],
                timeout=1,
                stream=True,
                on_line=lambda _line: None,
            )
        )
    time.sleep(0.5)
    survivors = subprocess.run(
        ["/bin/ps", "-Ao", "args"], capture_output=True, text=True, check=False
    ).stdout
    assert marker not in survivors, "the child outlived the timeout"


def test_a_child_that_floods_stderr_does_not_deadlock() -> None:
    """stderr has its own ~64 KiB pipe buffer and was only read after stdout hit
    EOF, so a child that filled it blocked writing while abox blocked reading —
    with no timeout to break it. `docker build` puts the whole BuildKit progress
    stream on stderr, so this was one long build away from happening for real.
    """
    noise = "x" * 40
    script = (
        f"i=0; while [ $i -lt 4000 ]; do echo '{noise}' >&2; i=$((i+1)); done; echo done"
    )
    result = bounded(lambda: shell.run(["/bin/sh", "-c", script], timeout=20, stream=True))
    assert result.ok
    assert len(result.stderr) > 64 * 1024, "stderr was truncated"
    assert "done" in result.stdout


def test_the_non_streaming_path_reports_a_timeout_the_same_way() -> None:
    """`subprocess.run` raised TimeoutExpired, which is not an AboxError, so a
    timeout reached the user as a traceback on the one path where it could
    already fire."""
    with pytest.raises(CommandTimeoutError, match="exceeded its"):
        bounded(lambda: shell.run(["/bin/sh", "-c", "sleep 20"], timeout=1))
