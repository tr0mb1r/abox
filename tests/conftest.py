"""Shared fixtures.

Every test runs against a redirected config/state tree and, where a subprocess
would otherwise be involved, a recording fake runner. Nothing here touches the
operator's real Docker daemon, keychain, or ``~/.config``.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from abox import shell
from abox.manifest import GlobalConfig, Manifest, MountsConfig, ProfileConfig, RunConfig


@pytest.fixture(autouse=True)
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Redirect every abox path into ``tmp_path``."""
    config_home = tmp_path / "config"
    state_home = tmp_path / "state"
    config_home.mkdir(parents=True)
    state_home.mkdir(parents=True)
    monkeypatch.setenv("ABOX_CONFIG_HOME", str(config_home))
    monkeypatch.setenv("ABOX_STATE_HOME", str(state_home))
    monkeypatch.setenv("ABOX_DOCKER_MCP_HOME", str(tmp_path / "docker-mcp"))
    yield tmp_path


@dataclass
class RecordedCall:
    argv: tuple[str, ...]
    stdin_data: str | None
    cwd: Path | None

    @property
    def line(self) -> str:
        return " ".join(self.argv)


@dataclass
class FakeRunner:
    """A ``shell`` runner that scripts responses and records every invocation."""

    responses: list[tuple[re.Pattern[str], shell.Result]] = field(default_factory=list)
    calls: list[RecordedCall] = field(default_factory=list)
    default: tuple[int, str, str] = (0, "", "")

    def expect(
        self, pattern: str, stdout: str = "", *, returncode: int = 0, stderr: str = ""
    ) -> None:
        self.responses.append(
            (re.compile(pattern), shell.Result((), returncode, stdout, stderr))
        )

    def __call__(self, argv: Sequence[str], opts: shell.RunOptions) -> shell.Result:
        argv = tuple(argv)
        self.calls.append(RecordedCall(argv, opts.stdin_data, opts.cwd))
        line = " ".join(argv)
        for pattern, result in self.responses:
            if pattern.search(line):
                return shell.Result(argv, result.returncode, result.stdout, result.stderr)
        code, out, err = self.default
        return shell.Result(argv, code, out, err)

    def find(self, needle: str) -> list[RecordedCall]:
        return [call for call in self.calls if needle in call.line]

    @property
    def argv_blob(self) -> str:
        """Everything that ever reached argv — used to assert secrets did not."""
        return "\n".join(call.line for call in self.calls)


@pytest.fixture
def runner() -> Iterator[FakeRunner]:
    fake = FakeRunner()
    with shell.using_runner(fake):
        yield fake


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "project"
    ws.mkdir()
    (ws / "pyproject.toml").write_text("[project]\nname='demo'\n")
    (ws / ".env").write_text("TOKEN=hunter2\n")
    (ws / ".env.local").write_text("OTHER=1\n")
    secrets_dir = ws / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "key.pem").write_text("-----BEGIN-----\n")
    git = ws / ".git"
    git.mkdir()
    (git / "config").write_text('[core]\n\trepositoryformatversion = 0\n')
    (git / "hooks").mkdir()
    return ws


@pytest.fixture
def config() -> GlobalConfig:
    return GlobalConfig(
        profiles={"dev": ProfileConfig(port=8811), "secops": ProfileConfig(port=8812)}
    )


@pytest.fixture
def manifest() -> Manifest:
    return Manifest(
        project="demo",
        profile="dev",
        servers=["github-official", "duckduckgo"],
        toolchains=["python"],
        mounts=MountsConfig(mask=[".env*", "secrets/"]),
        egress=["github.com", "pypi.org"],
        run=RunConfig(),
    )


@pytest.fixture
def catalog_file(tmp_path: Path) -> Path:
    """A minimal v3 Docker MCP catalog, in the shape Docker Desktop writes."""
    directory = tmp_path / "docker-mcp" / "catalogs"
    directory.mkdir(parents=True)
    path = directory / "docker-mcp.yaml"
    path.write_text(
        """
version: 3
name: docker-mcp
displayName: Docker MCP Catalog
registry:
  github-official:
    description: GitHub's official MCP server.
    title: GitHub Official
    type: server
    image: ghcr.io/github/github-mcp-server@sha256:__GH__
    secrets:
      - name: github.personal_access_token
        env: GITHUB_PERSONAL_ACCESS_TOKEN
    allowHosts:
      - api.github.com:443
    tools:
      - name: list_issues
      - name: create_pull_request
  duckduckgo:
    description: Web search.
    title: DuckDuckGo
    type: server
    image: mcp/duckduckgo@sha256:__DDG__
    tools:
      - name: search
  floating:
    description: Server pinned to a mutable tag.
    title: Floating
    type: server
    image: mcp/floating:latest
    tools:
      - name: whatever
"""
.replace("__GH__", "d" * 64).replace("__DDG__", "0" * 64),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def runner_fake(runner: FakeRunner) -> FakeRunner:
    """Alias for modules that already bind the name ``runner`` to ``abox.runner``."""
    return runner
