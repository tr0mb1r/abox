"""Interactive flows for ``abox init`` and friends.

The picker's job is to make the *safe* manifest the easy one: toolchains are
detected rather than typed, egress is proposed from what those toolchains
actually need, and every MCP server shows whether it will demand a secret before
it is selected.
"""

from __future__ import annotations

import configparser
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import questionary

from . import secrets as secrets_mod
from .catalog import Catalog, CatalogServer
from .errors import AboxError
from .manifest import (
    BASE_MANDATORY_EGRESS,
    TOOLCHAINS,
    GlobalConfig,
    Manifest,
    ProfileConfig,
    _check_host,
)

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


def _selectable(choices: Sequence[questionary.Choice]) -> bool:
    """Is there anything here the cursor can actually land on?

    ``Separator`` is a ``Choice`` with ``disabled="-"``, so a list of nothing but
    headings is still zero *choices* as far as questionary is concerned — and
    walks into the same crash an empty list does. The grouped server picker made
    that reachable, so the guard counts selectable entries rather than entries.
    """
    return any(not choice.disabled for choice in choices)


def checkbox(message: str, choices: Sequence[questionary.Choice], **kwargs: Any) -> list[str]:
    """``questionary.checkbox`` that tolerates an empty choice list.

    questionary crashes on zero choices — it reads ``pointed_at`` before that
    attribute exists — so every checkbox in this module goes through here. An
    empty list is a perfectly ordinary state: a project with no detected
    toolchain and no git remote has nothing to suggest.
    """
    if not _selectable(choices):
        return []
    picked = questionary.checkbox(message, choices=list(choices), **kwargs).ask()
    if picked is None:
        raise AboxError("cancelled")
    return list(picked)


def select_one(
    message: str,
    choices: Sequence[questionary.Choice],
    *,
    default: str | None = None,
    **kwargs: Any,
) -> str:
    """``questionary.select`` with the same empty-list and cancel handling."""
    if not _selectable(choices):
        raise AboxError(f"nothing to choose from: {message}")
    picked = questionary.select(message, choices=list(choices), default=default, **kwargs).ask()
    if picked is None:
        raise AboxError("cancelled")
    return str(picked)


def ask_text(message: str, **kwargs: Any) -> str:
    picked = questionary.text(message, **kwargs).ask()
    if picked is None:
        raise AboxError("cancelled")
    return str(picked)


def ask_confirm(message: str, *, default: bool = True, **kwargs: Any) -> bool:
    """Unlike the raw prompt, Ctrl-C here is a cancel, not a silent 'no'.

    ``pick_tools`` used to read ``None`` as "do not narrow", which under the
    review screen would mean Ctrl-C quietly answering a question for you.
    """
    picked = questionary.confirm(message, default=default, **kwargs).ask()
    if picked is None:
        raise AboxError("cancelled")
    return bool(picked)


# -- the answers -----------------------------------------------------------


@dataclass
class InitDraft:
    """Every answer ``abox init`` collects, in one mutable place.

    The review screen edits this in place and hands it back; nothing reaches
    disk until the caller writes the manifest. That ordering is the whole point
    — see ``created_profiles``.
    """

    project: str
    profile: str
    servers: list[str] = field(default_factory=list)
    tools: dict[str, list[str]] = field(default_factory=dict)
    toolchains: list[str] = field(default_factory=list)
    egress: list[str] = field(default_factory=list)
    mask: list[str] = field(default_factory=list)
    context: list[str] = field(default_factory=list)
    permission_mode: str = "default"
    #: Profiles invented during this run. The caller persists them only once the
    #: manifest is written: saving them here, as the picker used to, left an
    #: orphan profile holding a port behind every cancelled init.
    created_profiles: dict[str, ProfileConfig] = field(default_factory=dict)
    #: Names of secrets stored during this run — never values. The summary and
    #: the cancel notice name them, so a stored credential is never silent.
    stored_secrets: list[str] = field(default_factory=list)


@dataclass
class InitContext:
    """Everything the editors need that is not itself an answer."""

    workspace: Path
    catalog: Catalog
    config: GlobalConfig
    manifest_path: Path
    detected: list[str] = field(default_factory=list)


def seed_draft(
    *,
    project: str,
    workspace: Path,
    config: GlobalConfig,
    existing: Manifest | None,
    profile: str | None = None,
    servers: Sequence[str] | None = None,
    detected: Sequence[str] | None = None,
) -> InitDraft:
    """The starting point for every path through ``abox init``.

    ``--yes`` writes this untouched; Quick setup opens the review screen on it;
    Custom overwrites it answer by answer. One function so the non-interactive
    defaults and the interactive pre-fill cannot drift apart — they were
    separate branches of the same ``if``, and only the non-interactive one
    remembered ``BASE_MANDATORY_EGRESS``.
    """
    found = list(detected if detected is not None else detect_toolchains(workspace))
    toolchains = list(existing.toolchains) if existing else found
    return InitDraft(
        project=project,
        profile=profile or (existing.profile if existing else next(iter(config.profiles))),
        servers=list(servers or (existing.servers if existing else [])),
        tools=dict(existing.tools) if existing else {},
        toolchains=toolchains,
        egress=list(
            dict.fromkeys(
                [
                    *(existing.egress if existing else []),
                    *suggest_egress(toolchains, workspace),
                    *BASE_MANDATORY_EGRESS,
                ]
            )
        ),
        mask=list(existing.mounts.mask) if existing else [],
        context=list(existing.mounts.context) if existing else [],
        permission_mode=existing.run.permission_mode.value if existing else "default",
    )


#: Group heading -> the question that puts a server in it. Order is the order
#: the user sees, and the first match wins, so a server never appears twice.
#: The Docker catalog carries no categories, so every one of these is derived
#: from a field abox already reads — and each says something about trust rather
#: than topic, which is the axis that matters when you are about to hand an
#: agent a tool.
SERVER_GROUPS: tuple[tuple[str, Callable[[CatalogServer], bool]], ...] = (
    ("ready to use", lambda s: not s.secrets),
    ("needs a secret — abox can set it for you next", lambda s: bool(s.secrets)),
)


def _server_marks(server: CatalogServer) -> str:
    marks: list[str] = []
    if server.secrets:
        plural = "s" if len(server.secrets) > 1 else ""
        marks.append(f"needs {len(server.secrets)} secret{plural}")
    if server.source == "custom":
        marks.append("custom")
    if server.is_remote:
        marks.append("remote")
    if not server.pinned and server.image:
        marks.append("UNPINNED")
    return f"  [{', '.join(marks)}]" if marks else ""


def _server_choice(server: CatalogServer, *, checked: bool) -> questionary.Choice:
    return questionary.Choice(
        title=f"{server.name:<28} {server.summary(56)}{_server_marks(server)}",
        value=server.name,
        checked=checked,
    )


def _server_choices(catalog: Catalog, preselected: Sequence[str]) -> list[questionary.Choice]:
    """Grouped, so a first-time reader is not handed 200 undifferentiated rows.

    Sorted case-insensitively within a group: ``catalog.names()`` is ASCII-sorted,
    which files ``SQLite`` before ``duckduckgo`` and reads as a bug.
    """
    chosen = [catalog.require(n) for n in catalog.names() if n in preselected]
    rest = [catalog.require(n) for n in catalog.names() if n not in preselected]

    choices: list[questionary.Choice] = []
    if chosen:
        choices.append(questionary.Separator("── already in this project ──"))
        for server in sorted(chosen, key=lambda s: s.name.lower()):
            choices.append(_server_choice(server, checked=True))

    # Custom servers last: they are the operator's own, so they need no
    # introduction, and burying them keeps the catalog's own entries on top.
    custom = [s for s in rest if s.source == "custom"]
    catalogued = [s for s in rest if s.source != "custom"]
    for heading, belongs in SERVER_GROUPS:
        members = sorted(
            (s for s in catalogued if belongs(s)), key=lambda s: s.name.lower()
        )
        if not members:
            continue
        choices.append(questionary.Separator(f"── {heading} ──"))
        choices.extend(_server_choice(s, checked=False) for s in members)
    if custom:
        choices.append(questionary.Separator("── your own (custom-servers.yaml) ──"))
        for server in sorted(custom, key=lambda s: s.name.lower()):
            choices.append(_server_choice(server, checked=False))
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
        "MCP servers — the tools the agent can call:",
        _server_choices(catalog, preselected),
        # The filter is a substring match over the rendered title, so "secret"
        # narrows to servers that want one and "git" matches name *and*
        # description. questionary refuses j/k alongside it — those keys are
        # filter input once search is on — so it must be turned off explicitly.
        use_search_filter=True,
        use_jk_keys=False,
        instruction="type to filter · space toggles · enter confirms",
    )


def pick_tools(
    catalog: Catalog, servers: Sequence[str], existing: dict[str, list[str]] | None = None
) -> dict[str, list[str]]:
    """Optional per-server narrowing. Empty selection means 'all tools'."""
    require_interactive("narrowing tools")
    existing = existing or {}
    out: dict[str, list[str]] = {}
    narrow = ask_confirm(
        "Narrow the tool set for any server?",
        default=bool(existing),
        instruction="no = the agent gets every tool each server offers",
    )
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
            instruction="space toggles · enter confirms",
        )
        # Selecting every tool is the same as not filtering at all; recording it
        # would only make the manifest drift as the server gains tools.
        if selected and len(selected) < len(server.tools):
            out[name] = list(selected)
    return out


def pick_profile(
    config: GlobalConfig,
    default: str | None = None,
    *,
    created: dict[str, ProfileConfig] | None = None,
) -> str:
    """Choose a gateway profile, optionally inventing one.

    A profile invented here is added to ``config`` in memory — so the next port
    allocation sees it — but deliberately **not** saved. It goes into ``created``
    for the caller to persist once the manifest is actually written; saving it
    here left an orphan profile, holding a port, behind every cancelled init.
    """
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
    picked = select_one(
        "Gateway profile:",
        choices,
        default=default if default in names else None,
        instruction="projects sharing a profile share one gateway container",
    )
    if picked != "__new__":
        return picked

    name = questionary.text("new profile name:").ask()
    if not name:
        raise AboxError("cancelled")
    used = {p.port for p in config.profiles.values()}
    port = 8811
    while port in used:
        port += 1
    profile = ProfileConfig(port=port)
    config.profiles[name] = profile
    if created is not None:
        created[name] = profile
    return str(name)


def pick_toolchains(detected: Sequence[str]) -> list[str]:
    require_interactive("choosing toolchains")
    return checkbox(
        "Toolchains to install in the container:",
        [
            questionary.Choice(title=name, value=name, checked=name in detected)
            for name in sorted(TOOLCHAINS)
        ],
        instruction="pre-ticked from what abox found in your repo",
    )


def _validate_egress_input(text: str) -> bool | str:
    """Reject at the prompt what the manifest would reject after the whole flow.

    ``_check_host`` is the model's own rule, so the picker and pydantic can never
    disagree about what a hostname is — and its messages already name the four
    ways this goes wrong (a URL, a path, a port, a wildcard).
    """
    for token in text.replace(",", " ").split():
        try:
            _check_host(token)
        except ValueError as exc:
            return str(exc)
    return True


def pick_egress(
    suggested: Sequence[str], existing: Sequence[str] = (), *, always_on: Sequence[str] = ()
) -> list[str]:
    """Choose the outbound allowlist.

    ``always_on`` hosts are kept out of the checkbox and appended to the result:
    offering a tickbox for something that cannot be turned off is a lie, and
    ``BASE_MANDATORY_EGRESS`` is re-added unconditionally at merge time anyway.
    """
    require_interactive("choosing egress")
    pinned = list(dict.fromkeys(always_on))
    merged: list[str] = []
    for host in (*existing, *suggested):
        if host not in merged and host not in pinned:
            merged.append(host)

    if pinned:
        questionary.print(
            f"  always allowed: {', '.join(pinned)}\n"
            "  (Claude Code cannot authenticate without them)",
            style="fg:ansibrightblack",
        )
    out = checkbox(
        "Allowed outbound domains:",
        [questionary.Choice(title=host, value=host, checked=True) for host in merged],
        instruction="untick to drop · everything not on this list is blocked",
    )
    if not merged:
        questionary.print(
            "Nothing to suggest for this project — no toolchain registry and no git\n"
            "remote were detected. Add anything else the agent will need.",
            style="fg:ansiyellow",
        )
    extra = ask_text(
        "additional domains (space or comma separated, blank to skip):",
        validate=_validate_egress_input,
    )
    for token in extra.replace(",", " ").split():
        if token not in out and token not in pinned:
            out.append(token)
    return [*out, *pinned]


def _validate_mask_input(text: str) -> bool | str:
    """The same rules ``MountsConfig`` enforces, surfaced while you can fix them."""
    for token in text.split():
        if token.startswith("/"):
            return f"{token!r} must be workspace-relative — drop the leading /"
        if ".." in Path(token).parts:
            return f"{token!r} must not escape the workspace with '..'"
    return True


def pick_masks(defaults: Sequence[str] = (), existing: Sequence[str] = ()) -> list[str]:
    """Extra paths to hide from the agent, on top of the global defaults.

    The old summary printed a ``masked`` line fed from the global defaults while
    the picker never asked for a project mask, so the one number a reader might
    act on was the one they could not change.
    """
    require_interactive("choosing masked paths")
    if defaults:
        questionary.print(
            f"  already masked everywhere: {', '.join(defaults)}",
            style="fg:ansibrightblack",
        )
    answer = ask_text(
        "Extra paths to hide from the agent (workspace-relative globs, blank for none):",
        default=" ".join(existing),
        validate=_validate_mask_input,
    )
    return [token for token in answer.split() if token]


def pick_permission_mode(default: str = "default") -> str:
    require_interactive("choosing a permission mode")
    return select_one(
        "Permission mode for headless runs:",
        [
            questionary.Choice(
                title="default           — agent asks before acting", value="default"
            ),
            questionary.Choice(
                title="acceptEdits       — file edits auto-approved", value="acceptEdits"
            ),
            questionary.Choice(
                title="plan              — agent may only plan", value="plan"
            ),
            questionary.Choice(
                title="bypassPermissions — no prompts; abox refuses to run unless "
                "every boundary check passes",
                value="bypassPermissions",
            ),
        ],
        default=default,
        instruction="how much the agent may do without asking you",
    )


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
    answer = ask_text(
        "Read-only context dirs to mount under /context (space separated, blank for none):",
        default=" ".join(existing),
        validate=_validate_context_input,
    )
    return [token for token in answer.split() if token]


# -- secrets ---------------------------------------------------------------


def offer_secrets(draft: InitDraft, ctx: InitContext) -> None:
    """Collect the secrets the chosen servers declare, while they are chosen.

    Picking a server marked ``needs 1 secret`` and then never being asked for it
    is the sharpest edge in the old flow: nothing fails until ``abox up``, by
    which point the connection between the two is gone.

    Deliberately the only place in this module that shells out to Docker, and
    only *after* an explicit yes — ``docker mcp secret ls`` has a 60s timeout, so
    calling it to draw a review row would hang ``abox init`` for a minute on a
    stopped daemon.
    """
    require_interactive("setting secrets")
    needed = ctx.catalog.secrets_for(draft.servers)
    if not needed:
        return
    if not ask_confirm(
        f"{len(needed)} of the servers you picked need a credential — set them now?",
        default=True,
        instruction="stored in Docker's secret store immediately, and kept even if "
        "you cancel this setup",
    ):
        questionary.print(
            "  later: abox secrets set <name>", style="fg:ansibrightblack"
        )
        return

    try:
        present = secrets_mod.docker_secret_names()
    except AboxError as exc:
        # Docker not running is an ordinary state during `abox init`; it must not
        # take the whole flow down with it.
        questionary.print(f"  secret store unreachable: {exc.message}", style="fg:ansiyellow")
        questionary.print(
            "  set them later with `abox secrets set <name>`", style="fg:ansibrightblack"
        )
        return

    missing = [name for name in needed if name not in present]
    if not missing:
        questionary.print(
            "  ✔ every credential these servers need is already stored",
            style="fg:ansigreen",
        )
        return

    for name in missing:
        answer = select_one(
            f"{name}:",
            [
                questionary.Choice(title="type it now (hidden)", value="type"),
                questionary.Choice(title="skip this one", value="skip"),
                questionary.Choice(title="skip the rest", value="stop"),
            ],
        )
        if answer == "stop":
            break
        if answer == "skip":
            continue
        value = secrets_mod.read_from_prompt(name)
        secrets_mod.set_secret(
            name, value, reference="(typed at the terminal)", source="prompt"
        )
        del value
        draft.stored_secrets.append(name)
        questionary.print(f"  ✔ stored {name} (value never logged)", style="fg:ansigreen")


# -- the review screen -----------------------------------------------------


def _summarise(values: Sequence[str], *, empty: str, limit: int = 3) -> str:
    """Never render a blank: an unset row has to say what unset *means*."""
    if not values:
        return empty
    head = ", ".join(values[:limit])
    rest = len(values) - limit
    return f"{head}  +{rest} more" if rest > 0 else head


def _tools_value(draft: InitDraft, ctx: InitContext) -> str:
    if not draft.tools:
        return "(all tools from every server)"
    parts = []
    for name, tools in sorted(draft.tools.items()):
        server = ctx.catalog.get(name)
        total = len(server.tools) if server and server.tools else len(tools)
        parts.append(f"{name}: {len(tools)} of {total}")
    return _summarise(parts, empty="(all tools from every server)", limit=2)


def _secrets_value(draft: InitDraft, ctx: InitContext) -> str:
    """Counted from the catalog only — drawing a row must never touch Docker."""
    needed = ctx.catalog.secrets_for(draft.servers)
    if not needed:
        return "(none needed)"
    stored = [n for n in needed if n in draft.stored_secrets]
    return f"{len(needed)} needed, {len(stored)} set here — {_summarise(needed, empty='', limit=2)}"


def _egress_value(draft: InitDraft, ctx: InitContext) -> str:
    always = set(ctx.config.defaults.egress_mandatory) | set(BASE_MANDATORY_EGRESS)
    listed = [h for h in draft.egress if h not in always]
    if not listed:
        return f"(only the {len(always)} Claude Code cannot run without)"
    # Count first, sample second: the number is what a reader acts on, and a
    # long registry hostname would otherwise push it off an 80-column screen.
    return f"{len(listed)} + {len(always)} always-on — {_summarise(listed, empty='', limit=2)}"


def _profile_value(draft: InitDraft, ctx: InitContext) -> str:
    profile = ctx.config.profiles.get(draft.profile)
    return f"{draft.profile}" + (f"  (port {profile.port})" if profile else "")


def _mask_value(draft: InitDraft, ctx: InitContext) -> str:
    defaults = len(ctx.config.defaults.mask)
    return _summarise(draft.mask, empty=f"({defaults} from global defaults)")


@dataclass(frozen=True)
class Row:
    """One editable setting: how it reads, and how it is changed."""

    key: str
    label: str
    help: str
    value: Callable[[InitDraft, InitContext], str]
    edit: Callable[[InitDraft, InitContext], None]


def _edit_profile(draft: InitDraft, ctx: InitContext) -> None:
    draft.profile = pick_profile(ctx.config, draft.profile, created=draft.created_profiles)


def _edit_servers(draft: InitDraft, ctx: InitContext) -> None:
    draft.servers = pick_servers(ctx.catalog, draft.servers)
    # Drop narrowing for servers that are no longer declared, or the manifest
    # fails validation on a `tools` key with no matching server.
    draft.tools = {k: v for k, v in draft.tools.items() if k in draft.servers}
    offer_secrets(draft, ctx)


def _edit_tools(draft: InitDraft, ctx: InitContext) -> None:
    draft.tools = pick_tools(ctx.catalog, draft.servers, draft.tools)


def _edit_toolchains(draft: InitDraft, ctx: InitContext) -> None:
    draft.toolchains = pick_toolchains(draft.toolchains)


def _edit_egress(draft: InitDraft, ctx: InitContext) -> None:
    always = list(
        dict.fromkeys([*BASE_MANDATORY_EGRESS, *ctx.config.defaults.egress_mandatory])
    )
    # Suggest from the toolchains currently in the draft, not the ones detected
    # before the picker ran: ticking `python` by hand in a repo with no
    # pyproject.toml should still offer pypi.org.
    draft.egress = pick_egress(
        suggest_egress(draft.toolchains, ctx.workspace),
        draft.egress,
        always_on=always,
    )


def _edit_mask(draft: InitDraft, ctx: InitContext) -> None:
    draft.mask = pick_masks(ctx.config.defaults.mask, draft.mask)


def _edit_context(draft: InitDraft, ctx: InitContext) -> None:
    draft.context = pick_context_dirs(draft.context)


def _edit_permission(draft: InitDraft, ctx: InitContext) -> None:
    draft.permission_mode = pick_permission_mode(draft.permission_mode)


ROWS: tuple[Row, ...] = (
    Row(
        "profile",
        "gateway profile",
        "projects sharing a profile share one gateway container",
        _profile_value,
        _edit_profile,
    ),
    Row(
        "servers",
        "MCP servers",
        "the tools the agent can call — everything else it cannot reach",
        lambda d, c: _summarise(d.servers, empty="(none — the agent gets no MCP tools)"),
        _edit_servers,
    ),
    Row(
        "secrets",
        "server credentials",
        "the secrets those servers declare; abox can store them for you",
        _secrets_value,
        lambda d, c: offer_secrets(d, c),
    ),
    Row(
        "tools",
        "tool narrowing",
        "optionally hand the agent only some of a server's tools",
        _tools_value,
        _edit_tools,
    ),
    Row(
        "toolchains",
        "toolchains",
        "language runtimes installed in the container image",
        lambda d, c: _summarise(d.toolchains, empty="(none — no language runtime)"),
        _edit_toolchains,
    ),
    Row(
        "egress",
        "allowed domains",
        "the only hosts the agent may reach; everything else is dropped",
        _egress_value,
        _edit_egress,
    ),
    Row(
        "mask",
        "masked paths",
        "files in your repo the agent must not see",
        _mask_value,
        _edit_mask,
    ),
    Row(
        "context",
        "context dirs",
        "host folders mounted read-only under /context",
        lambda d, c: _summarise(d.context, empty="(none)"),
        _edit_context,
    ),
    Row(
        "permission",
        "permission mode",
        "how much the agent may do unattended",
        lambda d, c: d.permission_mode,
        _edit_permission,
    ),
)

SAVE = "__save__"
CANCEL = "__cancel__"

#: Budget for one review row, a little under the 80-column floor. A row that
#: wraps makes prompt_toolkit's cursor jump on every keystroke, and a value is a
#: glance, not a document — the editor behind it shows the whole list.
HUB_WIDTH = 78


def _fit(text: str, budget: int) -> str:
    return text if len(text) <= budget else text[: budget - 1].rstrip() + "…"


def _hub_choices(draft: InitDraft, ctx: InitContext) -> list[questionary.Choice]:
    width = max(len(row.label) for row in ROWS)
    budget = HUB_WIDTH - width - 6  # questionary's pointer, plus the gap
    choices: list[questionary.Choice] = [
        questionary.Choice(
            title=f"{row.label:<{width}}   {_fit(row.value(draft, ctx), budget)}",
            value=row.key,
            description=row.help,
        )
        for row in ROWS
    ]
    choices.append(questionary.Separator(" "))
    choices.append(
        questionary.Choice(
            title=f"✔ Save — write {ctx.manifest_path.name} and render the container",
            value=SAVE,
            description="nothing has touched disk until you pick this",
        )
    )
    choices.append(
        questionary.Choice(
            title="✖ Cancel — write nothing",
            value=CANCEL,
            description="the answers above are discarded",
        )
    )
    return choices


def choose_setup_mode(project: str, *, existing: bool = False) -> str:
    """``"quick"`` or ``"custom"``. Both land on the review screen."""
    require_interactive("choosing a setup mode")
    first = (
        questionary.Choice(
            title="Review  — keep the current settings and change what you want",
            value="quick",
            description="you land straight on the review screen",
        )
        if existing
        else questionary.Choice(
            title="Quick   — start from what abox detected, then review it",
            value="quick",
            description="fastest: the review screen opens with every setting filled in",
        )
    )
    return select_one(
        f"{'Editing' if existing else 'New sandbox for'} {project} — how do you want to start?",
        [
            first,
            questionary.Choice(
                title="Custom  — answer each question, then review",
                value="custom",
                description="same review screen at the end; every answer stays editable",
            ),
        ],
        default="quick",
        instruction="nothing is written until you say so",
        show_description=True,
    )


def walk_all(draft: InitDraft, ctx: InitContext) -> None:
    """Ask every question once, then hand over to the review screen.

    Cancelling here drops to the review screen rather than losing the answers
    already given — the old flow threw away everything for one wrong keystroke.
    """
    for row in ROWS:
        try:
            row.edit(draft, ctx)
        except AboxError as exc:
            _report(exc)
            questionary.print(
                "  jumping to the review screen — nothing you answered is lost",
                style="fg:ansibrightblack",
            )
            return


def _report(exc: AboxError) -> None:
    questionary.print(f"  ✖ {exc.message}", style="fg:ansired")
    if exc.hint:
        questionary.print(f"    ↳ {exc.hint}", style="fg:ansibrightblack")


def review_and_edit(draft: InitDraft, ctx: InitContext) -> bool:
    """The review screen. ``True`` means write it.

    A loop rather than the old one-shot summary, because the summary was the
    only place that showed what you had built and the only place you could not
    change it: answering "no" printed `nothing written` and discarded the lot.

    A sub-prompt that fails or is cancelled returns here with its row unchanged,
    so Ctrl-C costs one answer instead of all of them. Ctrl-C *here* still
    cancels the whole init.
    """
    require_interactive("reviewing the setup")
    by_key = {row.key: row for row in ROWS}
    pointer: str | None = SAVE
    while True:
        picked = select_one(
            "Review — pick a line to change it:",
            _hub_choices(draft, ctx),
            default=pointer,
            instruction="↑↓ move · enter opens a line",
            show_description=True,
        )
        if picked == SAVE:
            return True
        if picked == CANCEL:
            return False
        row = by_key[picked]
        pointer = picked
        try:
            row.edit(draft, ctx)
        except AboxError as exc:
            _report(exc)
            questionary.print(f"  {row.label} unchanged", style="fg:ansibrightblack")
