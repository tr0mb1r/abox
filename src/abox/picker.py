"""Interactive flows for ``abox init`` and friends.

The picker's job is to make the *safe* manifest the easy one: toolchains are
detected rather than typed, egress is proposed from what those toolchains
actually need, and every MCP server shows whether it will demand a secret before
it is selected.
"""

from __future__ import annotations

import configparser
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

import questionary

from .catalog import Catalog
from .errors import AboxError
from .manifest import TOOLCHAINS, GlobalConfig, ProfileConfig

#: Registries each toolchain needs to fetch dependencies.
TOOLCHAIN_EGRESS: dict[str, tuple[str, ...]] = {
    "python": ("pypi.org", "files.pythonhosted.org"),
    "go": ("proxy.golang.org", "sum.golang.org", "storage.googleapis.com"),
    "node": ("registry.npmjs.org",),
    "rust": ("crates.io", "static.crates.io", "index.crates.io"),
    "java": ("repo.maven.apache.org", "repo1.maven.org"),
    "ruby": ("rubygems.org", "index.rubygems.org"),
    "php": ("repo.packagist.org", "packagist.org"),
    "dotnet": ("api.nuget.org",),
}

#: Marker file -> toolchain.
TOOLCHAIN_MARKERS: tuple[tuple[str, str], ...] = (
    ("pyproject.toml", "python"),
    ("requirements.txt", "python"),
    ("setup.py", "python"),
    ("uv.lock", "python"),
    ("go.mod", "go"),
    ("package.json", "node"),
    ("Cargo.toml", "rust"),
    ("pom.xml", "java"),
    ("build.gradle", "java"),
    ("build.gradle.kts", "java"),
    ("Gemfile", "ruby"),
    ("composer.json", "php"),
)

GIT_HOST_EGRESS: dict[str, tuple[str, ...]] = {
    "github.com": ("github.com", "api.github.com", "codeload.github.com"),
    "gitlab.com": ("gitlab.com",),
    "bitbucket.org": ("bitbucket.org",),
}


def interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def require_interactive(what: str) -> None:
    if not interactive():
        raise AboxError(
            f"{what} needs an interactive terminal",
            hint="pass the values as flags instead (see `abox init --help`)",
        )


# -- detection ------------------------------------------------------------


def detect_toolchains(workspace: Path) -> list[str]:
    found: list[str] = []
    for marker, toolchain in TOOLCHAIN_MARKERS:
        if (workspace / marker).exists() and toolchain not in found:
            found.append(toolchain)
    if (workspace / "src").is_dir() and any(workspace.glob("*.csproj")):
        found.append("dotnet")
    return found


def detect_git_remotes(workspace: Path) -> list[str]:
    """Read remote URLs straight from ``.git/config``.

    Deliberately not ``git remote -v``: running git in a workspace an agent may
    have touched would execute whatever aliases or hooks it left behind.
    """
    path = workspace / ".git" / "config"
    if not path.is_file():
        return []
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    try:
        parser.read_string(path.read_text(encoding="utf-8", errors="replace"))
    except configparser.Error:
        return []
    hosts: list[str] = []
    for section in parser.sections():
        if not section.startswith("remote"):
            continue
        url = parser.get(section, "url", fallback="")
        host = _host_from_git_url(url)
        if host and host not in hosts:
            hosts.append(host)
    return hosts


def _host_from_git_url(url: str) -> str:
    url = url.strip()
    if not url:
        return ""
    if url.startswith("git@"):
        return url.split("@", 1)[1].split(":", 1)[0]
    if "://" in url:
        rest = url.split("://", 1)[1]
        netloc = rest.split("/", 1)[0]
        return netloc.split("@")[-1].split(":")[0]
    return ""


def suggest_egress(toolchains: Iterable[str], workspace: Path) -> list[str]:
    out: list[str] = []
    for toolchain in toolchains:
        for host in TOOLCHAIN_EGRESS.get(toolchain, ()):
            if host not in out:
                out.append(host)
    for host in detect_git_remotes(workspace):
        for entry in GIT_HOST_EGRESS.get(host, (host,)):
            if entry not in out:
                out.append(entry)
    return out


# -- prompts --------------------------------------------------------------


def checkbox(message: str, choices: Sequence[questionary.Choice]) -> list[str]:
    """``questionary.checkbox`` that tolerates an empty choice list.

    questionary crashes on zero choices — it reads ``pointed_at`` before that
    attribute exists — so every checkbox in this module goes through here. An
    empty list is a perfectly ordinary state: a project with no detected
    toolchain and no git remote has nothing to suggest.
    """
    if not choices:
        return []
    picked = questionary.checkbox(message, choices=list(choices)).ask()
    if picked is None:
        raise AboxError("cancelled")
    return list(picked)



@dataclass
class InitAnswers:
    project: str
    profile: str
    servers: list[str]
    tools: dict[str, list[str]]
    toolchains: list[str]
    egress: list[str]
    mask: list[str]
    context: list[str]
    permission_mode: str


def _server_choices(catalog: Catalog, preselected: Sequence[str]) -> list[questionary.Choice]:
    choices: list[questionary.Choice] = []
    for name in catalog.names():
        server = catalog.require(name)
        marks: list[str] = []
        if server.secrets:
            marks.append(f"needs {len(server.secrets)} secret(s)")
        if server.source == "custom":
            marks.append("custom")
        if not server.pinned and server.image:
            marks.append("UNPINNED")
        suffix = f"  [{', '.join(marks)}]" if marks else ""
        summary = server.summary(56)
        choices.append(
            questionary.Choice(
                title=f"{name:<28} {summary}{suffix}",
                value=name,
                checked=name in preselected,
            )
        )
    return choices


def pick_servers(catalog: Catalog, preselected: Sequence[str] = ()) -> list[str]:
    require_interactive("selecting MCP servers")
    if not catalog.servers:
        raise AboxError(
            "the Docker MCP catalog is empty",
            hint="open Docker Desktop → MCP Toolkit once to materialise the catalog, "
            "or declare servers in ~/.config/abox/custom-servers.yaml",
        )
    return checkbox(
        "MCP servers for this project (space to toggle, enter to confirm):",
        _server_choices(catalog, preselected),
    )


def pick_tools(
    catalog: Catalog, servers: Sequence[str], existing: dict[str, list[str]] | None = None
) -> dict[str, list[str]]:
    """Optional per-server narrowing. Empty selection means 'all tools'."""
    require_interactive("narrowing tools")
    existing = existing or {}
    out: dict[str, list[str]] = {}
    narrow = questionary.confirm(
        "Narrow the tool set for any server? (default: every tool the server offers)",
        default=bool(existing),
    ).ask()
    if not narrow:
        return {}
    for name in servers:
        server = catalog.get(name)
        if not server or not server.tools:
            continue
        selected = checkbox(
            f"tools for {name} (leave empty for all {len(server.tools)}):",
            [
                questionary.Choice(
                    title=tool, value=tool, checked=tool in existing.get(name, [])
                )
                for tool in server.tools
            ],
        )
        # Selecting every tool is the same as not filtering at all; recording it
        # would only make the manifest drift as the server gains tools.
        if selected and len(selected) < len(server.tools):
            out[name] = list(selected)
    return out


def pick_profile(config: GlobalConfig, default: str | None = None) -> str:
    require_interactive("choosing a profile")
    names = sorted(config.profiles)
    choices = [
        questionary.Choice(
            title=f"{name}  (port {config.profiles[name].port})"
            + (
                f" - {config.profiles[name].description}"
                if config.profiles[name].description
                else ""
            ),
            value=name,
        )
        for name in names
    ]
    choices.append(questionary.Choice(title="+ new profile…", value="__new__"))
    picked = questionary.select(
        "Gateway profile (projects sharing a profile share one gateway):",
        choices=choices,
        default=default if default in names else None,
    ).ask()
    if picked is None:
        raise AboxError("cancelled")
    if picked != "__new__":
        return str(picked)

    name = questionary.text("new profile name:").ask()
    if not name:
        raise AboxError("cancelled")
    used = {p.port for p in config.profiles.values()}
    port = 8811
    while port in used:
        port += 1
    config.profiles[name] = ProfileConfig(port=port)
    config.save()
    return str(name)


def pick_toolchains(detected: Sequence[str]) -> list[str]:
    require_interactive("choosing toolchains")
    return checkbox(
        "Toolchains to install in the container:",
        [
            questionary.Choice(title=name, value=name, checked=name in detected)
            for name in sorted(TOOLCHAINS)
        ],
    )


def pick_egress(suggested: Sequence[str], existing: Sequence[str] = ()) -> list[str]:
    require_interactive("choosing egress")
    merged: list[str] = []
    for host in (*existing, *suggested):
        if host not in merged:
            merged.append(host)

    out = checkbox(
        "Allowed outbound domains (everything else is dropped):",
        [questionary.Choice(title=host, value=host, checked=True) for host in merged],
    )
    if not merged:
        questionary.print(
            "Nothing to suggest for this project — no toolchain registry and no git\n"
            "remote were detected. api.anthropic.com and the profile gateway are\n"
            "always allowed; add anything else the agent will need.",
            style="fg:ansiyellow",
        )
    extra = questionary.text(
        "additional domains (space or comma separated, blank to skip):"
    ).ask()
    if extra is None:
        raise AboxError("cancelled")
    for token in extra.replace(",", " ").split():
        if token not in out:
            out.append(token)
    return out


def pick_permission_mode(default: str = "default") -> str:
    require_interactive("choosing a permission mode")
    picked = questionary.select(
        "Permission mode for headless runs:",
        choices=[
            questionary.Choice(
                title="default          — agent asks before acting", value="default"
            ),
            questionary.Choice(
                title="acceptEdits      — file edits auto-approved", value="acceptEdits"
            ),
            questionary.Choice(
                title="plan             — agent may only plan", value="plan"
            ),
            questionary.Choice(
                title="bypassPermissions — no prompts; abox refuses unless every "
                "boundary check passes",
                value="bypassPermissions",
            ),
        ],
        default=default,
    ).ask()
    if picked is None:
        raise AboxError("cancelled")
    return str(picked)


def _validate_context_input(text: str) -> bool | str:
    """Correct the operator in place rather than after the whole flow."""
    for token in text.split():
        path = Path(token).expanduser()
        if not path.is_absolute():
            return f"{token!r} must be an absolute or ~-anchored path"
        if not path.exists():
            return f"{path} does not exist"
    return True


def pick_context_dirs(existing: Sequence[str] = ()) -> list[str]:
    require_interactive("choosing context dirs")
    answer = questionary.text(
        "Read-only context dirs to mount under /context (space separated, blank for none):",
        default=" ".join(existing),
        validate=_validate_context_input,
    ).ask()
    if answer is None:
        raise AboxError("cancelled")
    return [token for token in answer.split() if token]


def confirm_summary(answers: InitAnswers, path: Path) -> bool:
    require_interactive("confirming")
    lines = [
        f"  project      {answers.project}",
        f"  profile      {answers.profile}",
        f"  servers      {', '.join(answers.servers) or '(none)'}",
        f"  toolchains   {', '.join(answers.toolchains) or '(none)'}",
        f"  egress       {', '.join(answers.egress) or '(none)'}",
        f"  masked       {', '.join(answers.mask) or '(none)'}",
        f"  permission   {answers.permission_mode}",
    ]
    questionary.print("\n".join(lines))
    return bool(questionary.confirm(f"write {path}?", default=True).ask())
