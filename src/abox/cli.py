"""The ``abox`` command line."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from . import __version__, dockerx, doctor, gateway, paths, picker, runner, telemetry
from . import catalog as catalog_mod
from . import proxy as proxy_mod
from . import render as render_mod
from . import secrets as secrets_mod
from . import shell as shell_mod
from .errors import AboxError
from .manifest import (
    GATEWAY_IMAGE_TAG,
    CustomServers,
    GlobalConfig,
    Manifest,
    RemoteSecret,
    RemoteServer,
    RemoteTransport,
    SecretsConfig,
    ServerNetwork,
    effective_allowlist,
    format_errors,
    merged_egress,
)

console = Console()
err_console = Console(stderr=True)

app = typer.Typer(
    name="abox",
    help="Sandboxed, network-restricted Claude Code environments with MCP via Docker.",
    no_args_is_help=True,
    add_completion=False,
)
mcp_app = typer.Typer(help="Manage the MCP servers this project declares.", no_args_is_help=True)
egress_app = typer.Typer(help="Manage the outbound allowlist.", no_args_is_help=True)
secrets_app = typer.Typer(help="Move secrets into the Docker secret store.", no_args_is_help=True)
gateway_app = typer.Typer(help="Manage per-profile MCP gateways.", no_args_is_help=True)
app.add_typer(mcp_app, name="mcp")
app.add_typer(egress_app, name="egress")
app.add_typer(secrets_app, name="secrets")
app.add_typer(gateway_app, name="gateway")

STATUS_STYLE = {
    doctor.Status.ok: "green",
    doctor.Status.warn: "yellow",
    doctor.Status.fail: "bold red",
    doctor.Status.skip: "dim",
}
STATUS_GLYPH = {
    doctor.Status.ok: "✔",
    doctor.Status.warn: "!",
    doctor.Status.fail: "✖",
    doctor.Status.skip: "-",
}


# -- helpers --------------------------------------------------------------


def _workspace(path: Path | None = None) -> Path:
    return paths.find_workspace(path)


def _load(path: Path | None = None) -> tuple[Path, Manifest, GlobalConfig]:
    workspace = _workspace(path)
    config = GlobalConfig.load()
    manifest = Manifest.load(workspace)
    config.profile(manifest.profile)  # fail fast on an unknown profile
    return workspace, manifest, config


def _catalog() -> tuple[catalog_mod.Catalog, CustomServers]:
    custom = CustomServers.load()
    return catalog_mod.load(custom=custom), custom


def _custom_for(manifest: Manifest) -> dict[str, object]:
    """The custom-servers.yaml entries this manifest actually names.

    Only these are written into the gateway's catalog — declaring a server in
    the global file should not expose it to every project on the profile.
    """
    custom = CustomServers.load()
    return {name: custom.servers[name] for name in manifest.servers if name in custom.servers}


def _spec(manifest: Manifest, config: GlobalConfig) -> gateway.GatewaySpec:
    return gateway.build_spec(
        manifest.profile,
        config,
        servers=manifest.servers,
        tools=sorted({t for tools in manifest.tools.values() for t in tools}),
        remote_servers=manifest.remote_servers,
        custom_servers=_custom_for(manifest),
        network_none=[
            name
            for name, mode in manifest.server_network.items()
            if mode is ServerNetwork.none
        ],
    )


def _bind(workspace: Path, manifest: Manifest) -> gateway.ProfileRegistry:
    return gateway.bind_project(
        manifest.profile,
        workspace=workspace,
        project=manifest.project,
        servers=manifest.servers,
        tools=manifest.tools,
        remote_servers=manifest.remote_servers,
        custom_servers=_custom_for(manifest),
        server_network=manifest.server_network,
    )


def _echo_checks(report: doctor.Report, *, verbose: bool = False) -> None:
    for check in report.checks:
        if check.status is doctor.Status.ok and not verbose:
            continue
        style = STATUS_STYLE[check.status]
        console.print(
            f"[{style}]{STATUS_GLYPH[check.status]}[/] {check.title}: {check.detail}"
        )
        if check.hint and check.status in (doctor.Status.fail, doctor.Status.warn):
            console.print(f"   [dim]↳ {check.hint}[/]")


def _fail(exc: AboxError) -> None:
    err_console.print(f"[bold red]error:[/] {exc.message}")
    if exc.hint:
        err_console.print(f"[dim]hint: {exc.hint}[/]")
    raise typer.Exit(exc.exit_code)


@app.callback(invoke_without_command=True)
def _root(
    version: Annotated[
        bool, typer.Option("--version", help="Print the abox version and exit.")
    ] = False,
) -> None:
    if version:
        console.print(f"abox {__version__}")
        raise typer.Exit(0)


# -- init -----------------------------------------------------------------


@app.command()
def init(
    directory: Annotated[
        Path | None, typer.Option("--dir", "-C", help="Project directory.")
    ] = None,
    project: Annotated[str | None, typer.Option(help="Project name (default: dir name).")] = None,
    profile: Annotated[
        str | None, typer.Option(help="Gateway profile. Seeds the review screen; still editable.")
    ] = None,
    servers: Annotated[
        list[str] | None,
        typer.Option("--server", help="Declare a server. Seeds the review screen; still editable."),
    ] = None,
    yes: Annotated[
        bool, typer.Option("--yes", "-y", help="Accept detected defaults, ask nothing.")
    ] = False,
) -> None:
    """Create (or update) agentbox.yaml and render the container artifacts.

    Opens a review screen with every setting already filled in from what abox
    detected; pick a line to change it, and nothing is written until you save.
    """
    try:
        workspace = (directory or Path.cwd()).expanduser().resolve()
        workspace.mkdir(parents=True, exist_ok=True)
        config = GlobalConfig.load()
        cat, _custom = _catalog()
        for warning in cat.warnings:
            console.print(f"[yellow]![/] {warning}")

        existing = None
        if paths.manifest_path(workspace).is_file():
            existing = Manifest.load(workspace)
            console.print(f"[dim]merging into existing {paths.manifest_path(workspace)}[/]")

        name = project or (existing.project if existing else workspace.name.lower())
        name = name.replace(" ", "-").lower()

        detected = picker.detect_toolchains(workspace)
        draft = picker.seed_draft(
            project=name,
            workspace=workspace,
            config=config,
            existing=existing,
            profile=profile,
            servers=servers,
            detected=detected,
        )

        if not yes and picker.interactive():
            ctx = picker.InitContext(
                workspace=workspace,
                catalog=cat,
                config=config,
                manifest_path=paths.manifest_path(workspace),
                detected=detected,
            )
            if picker.choose_setup_mode(name, existing=existing is not None) == "custom":
                picker.walk_all(draft, ctx)
            if not picker.review_and_edit(draft, ctx):
                console.print("[dim]nothing written[/]")
                _warn_orphan_secrets(draft)
                raise typer.Exit(0)

        manifest = _manifest_from(draft, config, existing)

        target = manifest.write(workspace)
        console.print(f"[green]✔[/] wrote {target}")
        if draft.created_profiles:
            # Deferred until the manifest exists: the picker used to save a new
            # profile the moment it was named, so cancelling left an orphan
            # profile holding a port in the global config.
            config.profiles.update(draft.created_profiles)
            config.save()
            for profile_name in draft.created_profiles:
                console.print(f"[green]✔[/] added profile {profile_name} to the global config")

        result = render_mod.render(manifest, config, workspace, _spec(manifest, config))
        written = render_mod.write(result)
        for name_, path in written.items():
            console.print(f"[green]✔[/] rendered {name_} → {path}")
        for warning in result.warnings:
            console.print(f"[yellow]![/] {warning}")

        _bind(workspace, manifest)
        if yes or not picker.interactive():
            console.print(
                f"\nnext: [bold]abox up[/] to build the image and start the "
                f"{manifest.profile} gateway"
            )
        else:
            _print_next_steps(manifest)
    except AboxError as exc:
        _fail(exc)


def _manifest_from(
    draft: picker.InitDraft, config: GlobalConfig, existing: Manifest | None
) -> Manifest:
    """Fold the answers over the existing manifest, rather than replacing it.

    ``init`` used to rebuild the model from scratch, which silently dropped every
    field the picker never asks about — ``env_secrets``, ``egress_ignored``,
    ``server_network``, ``mounts.watch``, and everything in ``run`` bar the
    permission mode. Both README and GUIDE promise "re-runs merge", and
    re-running ``init`` is now the documented way to re-edit a project, so this
    is load-bearing rather than tidy.
    """
    base = existing.model_dump(mode="json") if existing else {}
    mounts = {**base.get("mounts", {}), "mask": draft.mask, "context": draft.context}
    run = {
        **base.get("run", {}),
        "permission_mode": draft.permission_mode,
        "connectors": draft.connectors,
        "output": draft.output,
        "timeout": draft.timeout,
    }
    data = {
        **base,
        "project": draft.project,
        "profile": draft.profile,
        "servers": draft.servers,
        "tools": draft.tools,
        "toolchains": draft.toolchains,
        # Only for servers still declared: a `server_network` key naming a server
        # that is no longer in `servers` fails validation.
        "server_network": {k: v for k, v in draft.server_network.items() if k in draft.servers},
        "mounts": mounts,
        "egress": [e for e in draft.egress if e not in config.defaults.egress_mandatory],
        "run": run,
    }
    try:
        return Manifest.model_validate(data)
    except ValidationError as exc:
        # A typo in an answer is an ordinary mistake, not a crash. Report it
        # the way every other abox failure is reported.
        raise AboxError(
            "the answers do not make a valid manifest:\n" + format_errors(exc),
            hint="re-run `abox init` and correct the flagged answer",
        ) from exc


def _warn_orphan_secrets(draft: picker.InitDraft) -> None:
    """A secret typed during setup is already in Docker's store; say so.

    It cannot be rolled back by abandoning the init — ``docker mcp secret set``
    writes to the OS keychain, not to a file abox owns — so the honest move is
    to name what was stored rather than let it sit there unmentioned.
    """
    if not draft.stored_secrets:
        return
    console.print(
        f"[yellow]![/] {len(draft.stored_secrets)} credential(s) were stored during "
        f"setup and are still there: {', '.join(draft.stored_secrets)}"
    )
    console.print("   [dim]↳ `abox secrets rm <name>` if you did not mean to[/]")


def _print_next_steps(manifest: Manifest) -> None:
    console.print(
        f"\n[bold]Next:[/]\n"
        f"  [bold]1[/]  abox up            [dim]build the image, start the "
        f"{manifest.profile} gateway[/]\n"
        f"  [bold]2[/]  abox shell         [dim]then run `claude` inside and log in — "
        f"once per project[/]\n"
        f'  [bold]3[/]  abox run "…"       [dim]headless run; transcript captured[/]\n'
        f"\n[dim]Step 2 is not optional the first time: a fresh project has an empty "
        f"auth\nvolume, so `abox run` exits 1 at login. `abox doctor` audits the "
        f"sandbox\nat any point.[/]"
    )


# -- up / render ----------------------------------------------------------


@app.command()
def render(
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
) -> None:
    """Re-render the generated artifacts from the manifest."""
    try:
        workspace, manifest, config = _load(directory)
        result = render_mod.render(manifest, config, workspace, _spec(manifest, config))
        written = render_mod.write(result)
        for name, path in written.items():
            console.print(f"[green]✔[/] {name} → {path}")
        for warning in result.warnings:
            console.print(f"[yellow]![/] {warning}")
    except AboxError as exc:
        _fail(exc)


@app.command()
def up(
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
    no_build: Annotated[bool, typer.Option("--no-build", help="Skip the image build.")] = False,
    no_cache: Annotated[bool, typer.Option("--no-cache", help="Rebuild from scratch.")] = False,
    force_gateway: Annotated[
        bool, typer.Option("--force-gateway", help="Recreate the gateway container.")
    ] = False,
) -> None:
    """Ensure the network, the profile gateway, and the built agent image."""
    try:
        workspace, manifest, config = _load(directory)
        cat, _custom = _catalog()

        created = dockerx.ensure_network(config.network)
        console.print(
            f"[green]✔[/] network {config.network}" + (" (created)" if created else "")
        )

        registry = _bind(workspace, manifest)
        status = gateway.up(
            manifest.profile,
            config,
            cat,
            servers=registry.servers,
            tools=registry.tools,
            remote_servers=registry.remote_servers(),
            custom_servers=registry.custom_servers(),
            force=force_gateway,
        )
        console.print(
            f"[green]✔[/] gateway {status.container} healthy — {status.detail}\n"
            f"   [dim]{status.url} (servers: {', '.join(status.servers) or 'none'})[/]"
        )

        result = render_mod.render(manifest, config, workspace, _spec(manifest, config))
        render_mod.write(result)
        console.print(f"[green]✔[/] artifacts rendered ({len(result.masked_paths)} masked path(s))")
        for warning in result.warnings:
            console.print(f"[yellow]![/] {warning}")

        if config.egress_proxy.enabled:
            pstatus = proxy_mod.up(manifest, config, workspace, force=force_gateway)
            console.print(
                f"[green]✔[/] egress proxy {pstatus.container}: {pstatus.detail}\n"
                "   [dim]all agent 443 traffic is filtered here by SNI[/]"
            )
        else:
            proxy_mod.down(manifest.project)

        dockerx.ensure_volume(
            paths.claude_volume(workspace),
            labels={dockerx.LABEL_PROJECT: manifest.project},
        )
        # The token never rides the /opt/abox bind: that bind has to be readable
        # by whatever uid a container runs as, and this file is a bearer token
        # for a service holding the Docker socket.
        runner.stage_mcp_config(config, workspace)

        if no_build:
            console.print("[dim]skipping image build[/]")
            return
        console.print("[dim]building agent image…[/]")
        build = runner.build(
            manifest,
            workspace,
            no_cache=no_cache,
            on_line=lambda line: console.print(f"  [dim]{line[:160]}[/]"),
        )
        if not build.ok:
            raise AboxError(
                "docker build failed",
                hint=(build.stderr or build.stdout).strip()[-600:],
            )
        runspec = runner.load_runspec(workspace)
        console.print(f"[green]✔[/] agent image built: {runspec['image']}")
        _prune_superseded_images(manifest.project, keep=str(runspec["image"]))
    except AboxError as exc:
        _fail(exc)


def _prune_superseded_images(project: str, *, keep: str) -> None:
    """Drop this project's older agent images once the new one exists.

    The tag is content-addressed, so every edit to the manifest builds a new one
    and used to leave the last behind forever — well over a gigabyte a time, and
    the review screen makes editing the normal thing to do. Only this project's
    ``abox-agent-*`` tags are ever considered, and only after the replacement has
    built: a failed build leaves you with the image you had.
    """
    superseded = [img for img in dockerx.agent_images(project) if img.tag != keep]
    if not superseded:
        return
    removed, reclaimed = [], 0
    for image in superseded:
        # A tag still referenced by a container is refused by Docker; that is the
        # right answer, so a refusal is skipped rather than forced.
        if dockerx.remove_image(image.tag):
            removed.append(image.tag)
            reclaimed += image.size
    if not removed:
        return
    console.print(
        f"[green]✔[/] reclaimed {_human_bytes(reclaimed)} "
        f"({len(removed)} superseded image{'s' if len(removed) > 1 else ''})"
    )


def _human_bytes(size: int) -> str:
    """Decimal units, to match what `docker image ls` prints."""
    value = float(size)
    for unit in ("B", "KB", "MB"):
        if value < 1000:
            return f"{value:.0f} {unit}"
        value /= 1000
    return f"{value:.1f} GB"


# -- run / shell ----------------------------------------------------------


@app.command()
def run(
    prompt: Annotated[str, typer.Argument(help="The prompt to run headlessly.")],
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
    resume: Annotated[str | None, typer.Option("--resume", help="Resume a session id.")] = None,
    continue_last: Annotated[
        bool, typer.Option("--continue", help="Continue the most recent session.")
    ] = False,
    keep: Annotated[
        bool, typer.Option("--keep", help="Leave the container in place for inspection.")
    ] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Only print the summary.")] = False,
) -> None:
    """Provision a disposable container and run one headless Claude session."""
    try:
        workspace, manifest, config = _load(directory)
        cat, _custom = _catalog()

        pre = doctor.preflight(manifest, config, workspace, catalog=cat)
        if pre.failures:
            _echo_checks(pre)
            raise AboxError(
                "preflight failed — refusing to run",
                hint="`abox doctor` for the full report, `abox up` to re-render",
            )
        for check in pre.warnings:
            console.print(f"[yellow]![/] {check.title}: {check.detail}")

        outcome = runner.run(
            manifest,
            config,
            workspace,
            cat,
            prompt,
            resume=resume,
            continue_last=continue_last,
            keep=keep,
            on_line=None if quiet else (lambda line: console.print(f"[dim]{line[:160]}[/]")),
            on_event=None if quiet else _print_stream_event,
        )

        console.print()
        console.print(
            f"[{'green' if outcome.ok else 'red'}]run {outcome.run_id}[/] "
            f"exit={outcome.exit_code} duration={outcome.duration_s:.1f}s"
        )
        if outcome.session_id:
            console.print(f"  session: {outcome.session_id}  [dim](abox run --resume …)[/]")
        if outcome.transcript:
            console.print(f"  transcript: {outcome.transcript}")
        if outcome.tool_calls:
            console.print(f"  tool calls: {len(outcome.tool_calls)}")
        if outcome.counters and outcome.counters.dropped_packets:
            console.print(
                f"  [yellow]firewall dropped {outcome.counters.dropped_packets} packet(s)[/]"
            )
        if outcome.denied:
            console.print("  [yellow]egress review queue:[/]")
            for entry in outcome.denied[:10]:
                console.print(f"    {entry.name} (x{entry.count})")
            console.print("    [dim]promote with `abox egress add <domain>`[/]")
        for warning in outcome.warnings:
            console.print(f"  [yellow]![/] {warning}")
        raise typer.Exit(outcome.exit_code)
    except AboxError as exc:
        _fail(exc)


def _print_stream_event(line: str) -> None:
    """Render Claude's stream-json into something readable."""
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return
    kind = event.get("type")
    if kind == "system" and event.get("subtype") == "init":
        console.print(f"[dim]session {event.get('session_id', '?')}[/]")
    elif kind == "assistant":
        for block in (event.get("message") or {}).get("content") or []:
            if block.get("type") == "text" and block.get("text", "").strip():
                console.print(block["text"].strip())
            elif block.get("type") == "tool_use":
                console.print(f"[cyan]→ {block.get('name')}[/]")
    elif kind == "result":
        console.print(f"[dim]result: {event.get('subtype', 'done')}[/]")


@app.command()
def shell(
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
    keep: Annotated[bool, typer.Option("--keep", help="Leave the container running.")] = False,
    allow_broken_firewall: Annotated[
        bool,
        typer.Option(
            "--allow-broken-firewall",
            help="Hand over the tty even if the container never reported a working "
            "firewall. The session then has unrestricted egress.",
        ),
    ] = False,
) -> None:
    """Open an interactive session in a fresh sandbox (also used for first login)."""
    try:
        workspace, manifest, config = _load(directory)
        # `abox run` builds the claude argv; an interactive shell does not. Say
        # so before handing over the tty, because the failure is silent: a bare
        # `claude` starts fine and reports no MCP servers.
        strict = " --strict-mcp-config" if manifest.run.single_mcp_endpoint else ""
        console.print(
            f"[dim]inside: `claude` is wrapped to pass --mcp-config "
            f"{render_mod.MCP_CONFIG_PATH}{strict}; `command claude` bypasses it "
            f"and sees no MCP servers.[/]"
        )
        outcome = runner.shell_session(
            manifest,
            config,
            workspace,
            keep=keep,
            require_firewall=not allow_broken_firewall,
        )
        console.print(
            f"[dim]session {outcome.run_id} ended (exit {outcome.exit_code}, "
            f"{outcome.duration_s:.0f}s)[/]"
        )
        # These were computed, recorded to telemetry, and then never shown. The
        # one that matters says the container reported no working firewall — the
        # single most important thing to tell someone who just spent a session
        # inside it, and it only ever reached `abox logs`.
        for warning in outcome.warnings:
            console.print(f"[yellow]![/] {warning}")
        if outcome.denied:
            console.print(f"[yellow]![/] {len(outcome.denied)} domain(s) in the egress queue")
        raise typer.Exit(outcome.exit_code)
    except AboxError as exc:
        _fail(exc)


# -- mcp ------------------------------------------------------------------


@mcp_app.command("list")
def mcp_list(
    all_servers: Annotated[
        bool, typer.Option("--all", help="List the whole catalog, not just this project.")
    ] = False,
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
) -> None:
    """Show declared servers (or the whole catalog with --all)."""
    try:
        cat, _custom = _catalog()
        names = cat.names()
        manifest = None
        if not all_servers:
            _workspace_path, manifest, _config = _load(directory)
            names = manifest.all_servers
            cat.servers.update(catalog_mod.remote_to_catalog(manifest.remote_servers))
        table = Table(box=None, pad_edge=False)
        table.add_column("server", style="bold")
        table.add_column("image / endpoint")
        table.add_column("secrets")
        table.add_column("source", style="dim")
        for name in names:
            server = cat.get(name)
            if server is None:
                table.add_row(name, "[red]not in catalog[/]", "", "")
                continue
            if server.is_remote:
                reference = f"[cyan]remote[/] {server.remote_url}"
            else:
                image = server.image or "-"
                reference = image if len(image) < 54 else image[:26] + "…" + image[-24:]
                if not server.pinned:
                    reference += "  [yellow](unpinned)[/]"
            table.add_row(
                name,
                reference,
                ", ".join(server.secrets) or "-",
                server.source,
            )
        console.print(table)
    except AboxError as exc:
        _fail(exc)


@mcp_app.command("cost")
def mcp_cost(
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
) -> None:
    """Estimate what the declared tool set costs the agent in context, per turn.

    MCP tool schemas are re-sent on every turn, so a wide server is a standing
    tax rather than a one-off. Measured from the live gateway, so it reflects
    the `tools:` narrowing actually in effect.
    """
    try:
        _workspace_path, manifest, config = _load(directory)
        cat, _custom = _catalog()
        status = gateway.status(manifest.profile, config)
        if not status.ok:
            raise AboxError(
                f"gateway for profile {manifest.profile!r} is not healthy: {status.detail}",
                hint="`abox up` first — this measures what the agent will really see",
            )
        registry = gateway.ProfileRegistry.load(manifest.profile)
        spec = gateway.build_spec(
            manifest.profile,
            config,
            servers=registry.servers,
            tools=registry.tools,
            remote_servers=registry.remote_servers(),
        )
        probe = gateway.probe(spec, want_tools=True, timeout=120)
        if not probe.ok:
            raise AboxError(f"could not list tools: {probe.detail}")

        grouped = gateway.attribute_tools(probe.tool_schemas, cat, spec.all_servers)
        total = gateway.tool_schema_cost(probe.tool_schemas) or 1
        loose = grouped.pop(gateway.UNATTRIBUTED, [])
        ranked = sorted(grouped.items(), key=lambda kv: -gateway.tool_schema_cost(kv[1]))

        table = Table(box=None, pad_edge=False)
        table.add_column("server", style="bold")
        table.add_column("tools", justify="right")
        table.add_column("~tokens", justify="right")
        table.add_column("share", justify="right")
        for server, schemas in ranked:
            cost = gateway.tool_schema_cost(schemas)
            table.add_row(server, str(len(schemas)), f"{cost:,}", f"{100 * cost // total}%")
        for schema in sorted(loose, key=lambda s: -gateway.tool_schema_cost([s])):
            cost = gateway.tool_schema_cost([schema])
            table.add_row(
                f"[dim]?[/] {schema.get('name', '?')}",
                "1",
                f"{cost:,}",
                f"{100 * cost // total}%",
            )
        console.print(table)
        console.print(
            f"\n[bold]{len(probe.tool_schemas)} tools ≈ {total:,} tokens per turn[/] "
            "[dim](re-sent every turn)[/]"
        )
        if loose:
            console.print(
                f"  [dim]{len(loose)} tool(s) marked ? — the gateway's tool list carries no "
                "server field, and no catalog entry names these. Declare `tools:` for a "
                "custom server to attribute them.[/]"
            )
        if not manifest.tools and ranked:
            worst, schemas = ranked[0]
            share = 100 * gateway.tool_schema_cost(schemas) // total
            console.print(
                f"  [dim]nothing narrowed — {worst} is {share}% of it; "
                f"narrow with `abox mcp add {worst} --tool <name>`[/]"
            )
    except AboxError as exc:
        _fail(exc)


@mcp_app.command("import")
def mcp_import(
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
    apply: Annotated[
        bool, typer.Option("--apply", help="Declare the importable ones in the manifest.")
    ] = False,
) -> None:
    """Show the MCP servers configured on this host and how each can reach the sandbox.

    abox starts a project with nothing, so your host's servers are deliberately
    absent until declared. This reports what you already have and which of it
    can come in through the gateway.
    """
    try:
        workspace, manifest, config = _load(directory)
        cat, _custom = _catalog()
        inventory = catalog_mod.host_inventory(cat)
        if not inventory:
            console.print("[dim]no MCP servers configured on this host[/]")
            raise typer.Exit(0)

        declared = set(manifest.all_servers)
        table = Table(box=None, pad_edge=False)
        table.add_column("server", style="bold")
        table.add_column("on the host", style="dim")
        table.add_column("status")
        importable: list[str] = []
        for entry in inventory:
            if entry.name in declared:
                status = "[green]already declared[/]"
            elif entry.importable:
                status = "[cyan]can be imported[/]"
                importable.append(entry.name)
            else:
                status = f"[yellow]no[/] [dim]— {entry.reason}[/]"
            table.add_row(entry.name, f"{entry.source}: {entry.detail}", status)
        console.print(table)

        if not importable:
            console.print("\n[dim]nothing new to import[/]")
        elif not apply:
            console.print(
                f"\n[dim]`abox mcp import --apply` to declare: {', '.join(importable)}[/]"
            )
        else:
            manifest.servers = [*manifest.servers, *importable]
            manifest.write(workspace)
            render_mod.write(
                render_mod.render(manifest, config, workspace, _spec(manifest, config))
            )
            _bind(workspace, manifest)
            console.print(f"\n[green]✔[/] declared {', '.join(importable)}")
            needed = secrets_mod.required_secrets(cat, importable)
            if needed:
                # Advisory only, and it comes *after* the manifest and the
                # artifacts are already written. An unreachable secret store is
                # a reason to say less, not a reason to fail a command that has
                # already done its work — `abox doctor` reports the store
                # properly, and this line would only ever have hinted at it.
                try:
                    present = secrets_mod.docker_secret_names()
                except AboxError:
                    console.print(
                        f"  secrets: {', '.join(needed)} "
                        "[dim](secret store unreachable — `abox doctor` to check)[/]"
                    )
                else:
                    missing = [s for s in needed if s not in present]
                    state = (
                        "[green](all present)[/]"
                        if not missing
                        else f"[yellow](missing: {', '.join(missing)})[/]"
                    )
                    console.print(f"  secrets: {', '.join(needed)} {state}")
            console.print("  [dim]`abox up` to apply to the gateway[/]")

        if not manifest.run.connectors:
            console.print(
                "\n[dim]claude.ai connectors (Gmail, Drive, Notion, …) are off. "
                "Many are in the catalog as remote servers — `abox mcp list --all` — "
                "which keeps them behind the gateway. To load them the claude.ai way "
                "instead, set `run.connectors: true` (a second, unmediated MCP path).[/]"
            )
    except AboxError as exc:
        _fail(exc)


@mcp_app.command("add-remote")
def mcp_add_remote(
    name: Annotated[str, typer.Argument(help="Name to expose the remote server under.")],
    url: Annotated[str, typer.Option("--url", help="https endpoint of the MCP server.")],
    transport: Annotated[
        str, typer.Option("--transport", help="streamable-http or sse.")
    ] = "streamable-http",
    header: Annotated[
        list[str] | None,
        typer.Option("--header", help="Header as 'Name: value'; may use ${ENV} from --secret."),
    ] = None,
    secret: Annotated[
        list[str] | None,
        typer.Option("--secret", help="'docker-secret-name=ENV_VAR' injected by the gateway."),
    ] = None,
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
) -> None:
    """Declare an internet-hosted MCP server, proxied through the gateway.

    The agent still sees exactly one MCP endpoint and never learns this URL: the
    gateway container makes the outbound connection and holds any credential.
    """
    try:
        workspace, manifest, config = _load(directory)
        headers: dict[str, str] = {}
        for raw in header or []:
            if ":" not in raw:
                raise AboxError(f"--header must look like 'Name: value', got {raw!r}")
            key, value = raw.split(":", 1)
            headers[key.strip()] = value.strip()
        secrets_list: list[RemoteSecret] = []
        for raw in secret or []:
            if "=" not in raw:
                raise AboxError(
                    f"--secret must look like 'docker-secret-name=ENV_VAR', got {raw!r}"
                )
            secret_name, env = raw.split("=", 1)
            secrets_list.append(RemoteSecret(name=secret_name.strip(), env=env.strip()))

        remote = RemoteServer(
            url=url,
            transport=RemoteTransport(transport),
            headers=headers,
            secrets=secrets_list,
        )
        manifest.remote_servers = {**manifest.remote_servers, name: remote}
        manifest.write(workspace)
        render_mod.write(render_mod.render(manifest, config, workspace, _spec(manifest, config)))
        _bind(workspace, manifest)
        console.print(f"[green]✔[/] added remote server {name} → {url}")
        if secrets_list:
            missing = [
                s.name
                for s in secrets_list
                if s.name not in secrets_mod.docker_secret_names()
            ]
            if missing:
                console.print(
                    f"  [yellow]missing secret(s):[/] {', '.join(missing)}\n"
                    f"  [dim]`abox secrets set {missing[0]}`[/]"
                )
        console.print("  [dim]`abox up` to apply to the gateway[/]")
    except (AboxError, ValueError) as exc:
        _fail(exc if isinstance(exc, AboxError) else AboxError(str(exc)))


@mcp_app.command("rm-remote")
def mcp_rm_remote(
    name: Annotated[str, typer.Argument()],
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
) -> None:
    """Remove a declared remote MCP server."""
    try:
        workspace, manifest, config = _load(directory)
        if name not in manifest.remote_servers:
            raise AboxError(f"{name!r} is not a declared remote server")
        manifest.remote_servers = {
            k: v for k, v in manifest.remote_servers.items() if k != name
        }
        manifest.tools = {k: v for k, v in manifest.tools.items() if k != name}
        manifest.write(workspace)
        render_mod.write(render_mod.render(manifest, config, workspace, _spec(manifest, config)))
        _bind(workspace, manifest)
        console.print(f"[green]✔[/] removed remote server {name}  [dim](`abox up` to apply)[/]")
    except AboxError as exc:
        _fail(exc)


@mcp_app.command("oauth")
def mcp_oauth(
    provider: Annotated[
        str | None, typer.Argument(help="OAuth provider to authorize (omit to list).")
    ] = None,
) -> None:
    """List or authorize OAuth apps for remote MCP servers.

    Authorization happens on the host through Docker's own flow; the resulting
    token lands in the OS keychain and is injected by the daemon, so it never
    reaches the agent.
    """
    try:
        if provider is None:
            result = shell_mod.run(["docker", "mcp", "oauth", "ls"], timeout=60)
            console.print(result.stdout.strip() or "[dim]no OAuth apps available[/]")
            return
        console.print(f"[dim]opening the {provider} authorization flow…[/]")
        result = shell_mod.run(
            ["docker", "mcp", "oauth", "authorize", provider], timeout=300
        )
        if not result.ok:
            raise AboxError(
                f"could not authorize {provider}: {result.stderr.strip()[:200]}",
                hint="`abox mcp oauth` with no argument lists the available providers",
            )
        console.print(f"[green]✔[/] authorized {provider}")
        console.print("  [dim]`abox up` to restart the gateway with the new credential[/]")
    except AboxError as exc:
        _fail(exc)


@mcp_app.command("add")
def mcp_add(
    server: Annotated[str, typer.Argument(help="Catalog or custom server name.")],
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
    tools: Annotated[
        list[str] | None, typer.Option("--tool", help="Restrict to these tools.")
    ] = None,
) -> None:
    """Declare a server in the manifest and re-render."""
    try:
        workspace, manifest, config = _load(directory)
        cat, _custom = _catalog()
        entry = cat.require(server)
        if server not in manifest.servers:
            manifest.servers = [*manifest.servers, server]
        if tools:
            manifest.tools = {**manifest.tools, server: list(tools)}
        manifest.write(workspace)
        render_mod.write(render_mod.render(manifest, config, workspace, _spec(manifest, config)))
        _bind(workspace, manifest)
        console.print(f"[green]✔[/] added {server}")
        if entry.secrets:
            console.print(
                f"  [yellow]needs secret(s):[/] {', '.join(entry.secrets)}\n"
                "  [dim]`abox secrets set <name>` or map a source in "
                "~/.config/abox/secrets.yaml[/]"
            )
        console.print("  [dim]`abox up` to apply to the gateway[/]")
    except AboxError as exc:
        _fail(exc)


@mcp_app.command("rm")
def mcp_rm(
    server: Annotated[str, typer.Argument()],
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
) -> None:
    """Remove a server from the manifest and re-render."""
    try:
        workspace, manifest, config = _load(directory)
        if server not in manifest.servers:
            raise AboxError(f"{server!r} is not declared in this manifest")
        manifest.servers = [s for s in manifest.servers if s != server]
        manifest.tools = {k: v for k, v in manifest.tools.items() if k != server}
        manifest.write(workspace)
        render_mod.write(render_mod.render(manifest, config, workspace, _spec(manifest, config)))
        _bind(workspace, manifest)
        console.print(f"[green]✔[/] removed {server}  [dim](`abox up` to apply)[/]")
    except AboxError as exc:
        _fail(exc)


# -- egress ---------------------------------------------------------------


@egress_app.command("list")
def egress_list(directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None) -> None:
    """Show the effective allowlist and the review queue."""
    try:
        workspace, manifest, config = _load(directory)
        allow = merged_egress(manifest, config)
        console.print("[bold]allowed[/]")
        for host in allow:
            marker = " [dim](mandatory)[/]" if host in config.defaults.egress_mandatory else ""
            console.print(f"  {host}{marker}")
        denied = telemetry.review_queue(
            workspace,
            effective_allowlist(manifest, config),
            ignored=manifest.egress_ignored,
        )
        if manifest.egress_ignored:
            console.print("\n[bold]ignored[/] [dim](decided against; hidden from the queue)[/]")
            for host in manifest.egress_ignored:
                console.print(f"  {host}")
        if denied:
            console.print("\n[bold yellow]looked up but denied — undecided[/]")
            for entry in denied:
                console.print(f"  {entry.name}  x{entry.count} over {entry.runs} run(s)")
    except AboxError as exc:
        _fail(exc)


@egress_app.command("add")
def egress_add(
    domains: Annotated[list[str], typer.Argument(help="Domains to allow.")],
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
) -> None:
    """Allow one or more domains and regenerate the firewall."""
    try:
        workspace, manifest, config = _load(directory)
        manifest.egress = [*manifest.egress, *domains]  # validator normalises + dedupes
        manifest.write(workspace)
        render_mod.write(render_mod.render(manifest, config, workspace, _spec(manifest, config)))
        console.print(f"[green]✔[/] allowlisted {', '.join(domains)}")
        console.print("  [dim]takes effect on the next `abox run` (fresh container)[/]")
    except AboxError as exc:
        _fail(exc)


@egress_app.command("ignore")
def egress_ignore(
    domains: Annotated[list[str], typer.Argument(help="Domains to stop asking about.")],
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
) -> None:
    """Record a decision NOT to allow a domain, so it leaves the review queue.

    The queue is only useful while it means "undecided". Without this, a domain
    you have already ruled on keeps reappearing until you stop reading the list.
    """
    try:
        workspace, manifest, _config = _load(directory)
        manifest.egress = [d for d in manifest.egress if d not in {x.lower() for x in domains}]
        manifest.egress_ignored = [*manifest.egress_ignored, *domains]
        manifest.write(workspace)
        console.print(
            f"[green]✔[/] ignoring {', '.join(domains)} — still blocked, no longer listed"
        )
    except AboxError as exc:
        _fail(exc)


@egress_app.command("unignore")
def egress_unignore(
    domains: Annotated[list[str], typer.Argument()],
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
) -> None:
    """Put a previously ignored domain back into the review queue."""
    try:
        workspace, manifest, _config = _load(directory)
        drop = {d.lower() for d in domains}
        manifest.egress_ignored = [d for d in manifest.egress_ignored if d not in drop]
        manifest.write(workspace)
        console.print(f"[green]✔[/] {', '.join(domains)} back in the review queue")
    except AboxError as exc:
        _fail(exc)


@egress_app.command("rm")
def egress_rm(
    domains: Annotated[list[str], typer.Argument()],
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
) -> None:
    """Remove domains from the allowlist."""
    try:
        workspace, manifest, config = _load(directory)
        drop = {d.lower() for d in domains}
        manifest.egress = [d for d in manifest.egress if d not in drop]
        manifest.write(workspace)
        render_mod.write(render_mod.render(manifest, config, workspace, _spec(manifest, config)))
        console.print(f"[green]✔[/] removed {', '.join(domains)}")
    except AboxError as exc:
        _fail(exc)


# -- secrets --------------------------------------------------------------


@secrets_app.command("sync")
def secrets_sync(
    only: Annotated[list[str] | None, typer.Option("--only", help="Sync just these.")] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Report without writing.")] = False,
    allow_loose_perms: Annotated[
        bool, typer.Option("--allow-loose-perms", help="Accept group/world-readable files.")
    ] = False,
    interactive: Annotated[
        bool, typer.Option("--interactive", help="Also prompt for source: prompt mappings.")
    ] = False,
) -> None:
    """Push every mapped source into the Docker secret store."""
    try:
        config = SecretsConfig.load()
        if not config.mappings:
            console.print(
                f"[dim]no mappings in {paths.secrets_config_path()} — "
                "nothing to sync. Use `abox secrets set <name>` for one-offs.[/]"
            )
            raise typer.Exit(0)
        reports = secrets_mod.sync(
            config,
            only=only,
            dry_run=dry_run,
            allow_loose_perms=allow_loose_perms,
            include_prompts=interactive,
        )
        _print_secret_reports(reports)
        if any(not r.ok for r in reports):
            raise typer.Exit(1)
    except AboxError as exc:
        _fail(exc)


@secrets_app.command("check")
def secrets_check(
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
) -> None:
    """Compare each source against the store. Values are never printed."""
    try:
        config = SecretsConfig.load()
        required: list[str] = []
        try:
            _workspace_path, manifest, _cfg = _load(directory)
            cat, _custom = _catalog()
            required = secrets_mod.required_secrets(cat, manifest.servers)
        except AboxError:
            pass  # outside a project: just check the global mappings
        reports = secrets_mod.check(config, required=required)
        if not reports:
            console.print("[dim]no secrets mapped and none required[/]")
            raise typer.Exit(0)
        _print_secret_reports(reports)
        if any(not r.ok for r in reports):
            raise typer.Exit(1)
    except AboxError as exc:
        _fail(exc)


@secrets_app.command("set")
def secrets_set(
    name: Annotated[
        str, typer.Argument(help="Docker secret name, e.g. github.personal_access_token")
    ],
    from_file: Annotated[
        Path | None, typer.Option("--file", help="Read the value from this file.")
    ] = None,
    from_env: Annotated[
        str | None, typer.Option("--env", help="Read the value from this env var.")
    ] = None,
    stdin: Annotated[bool, typer.Option("--stdin", help="Read the value from stdin.")] = False,
    allow_loose_perms: Annotated[bool, typer.Option("--allow-loose-perms")] = False,
) -> None:
    """Store one secret directly. No 1Password required."""
    try:
        if sum(map(bool, (from_file, from_env, stdin))) > 1:
            raise AboxError("choose exactly one of --file, --env, --stdin")
        if from_file:
            value = secrets_mod.read_from_file(str(from_file), allow_loose_perms=allow_loose_perms)
            reference, source = str(from_file), "file"
        elif from_env:
            value = secrets_mod.read_from_env(from_env)
            reference, source = f"${from_env}", "env"
        elif stdin:
            value = sys.stdin.read().rstrip("\n")
            if not value:
                raise AboxError("nothing on stdin")
            reference, source = "(stdin)", "stdin"
        else:
            value = secrets_mod.read_from_prompt(name)
            reference, source = "(typed at the terminal)", "prompt"
        secrets_mod.set_secret(name, value, reference=reference, source=source)
        del value
        console.print(f"[green]✔[/] stored {name} [dim](via {source}, value never logged)[/]")
    except AboxError as exc:
        _fail(exc)


@secrets_app.command("rm")
def secrets_rm(
    names: Annotated[list[str], typer.Argument(help="Docker secret names to remove.")],
    force: Annotated[
        bool, typer.Option("--force", help="Remove even if a project still references it.")
    ] = False,
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
) -> None:
    """Remove a secret from the Docker store.

    Refuses by default when a project still references it: the reverse index
    exists precisely so revocation is not a guess, and a container whose
    `se://` reference no longer resolves will not start.
    """
    try:
        present = secrets_mod.docker_secret_names()
        cat, _custom = _catalog()
        index = secrets_mod.usage_index(cat)

        blocked: dict[str, list[secrets_mod.SecretUse]] = {}
        for name in names:
            uses = index.get(name, [])
            if uses and not force:
                blocked[name] = uses
        if blocked:
            for name, uses in blocked.items():
                console.print(f"[bold red]✖[/] {name} is still referenced by:")
                for use in uses:
                    console.print(f"    {use.project} → {use.kind} [bold]{use.detail}[/]")
            raise AboxError(
                "refusing to remove a secret that is still in use",
                hint="detach or undeclare it first, or pass --force and expect "
                "those projects to fail at container start",
            )

        state = secrets_mod.SyncState.load()
        for name in names:
            if name not in present:
                console.print(f"[dim]{name} was not in the store[/]")
            elif secrets_mod.docker_secret_rm(name):
                console.print(f"[green]✔[/] removed {name}")
            else:
                console.print(f"[yellow]![/] could not remove {name}")
            # Drop the digest either way: keeping it would make a later `check`
            # compare against a secret that no longer exists.
            state.entries.pop(name, None)
            for use in index.get(name, []):
                console.print(
                    f"  [yellow]still referenced by {use.project} → {use.kind} {use.detail}[/]"
                )
        state.save()
    except AboxError as exc:
        _fail(exc)


@secrets_app.command("attach")
def secrets_attach(
    pairs: Annotated[
        list[str], typer.Argument(help="ENV_VAR=docker-secret-name, e.g. GH_TOKEN=some.token")
    ],
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
) -> None:
    """Hand a stored secret to the agent as an environment variable.

    This is the one place abox gives the agent a credential. The value is passed
    as an `se://` reference the Docker daemon resolves at container start, so
    abox never reads it — but the agent can, and so can anyone who can run
    `docker inspect` on the container. `abox doctor` reports it on every run.
    """
    try:
        workspace, manifest, config = _load(directory)
        mapping = dict(manifest.env_secrets)
        for raw in pairs:
            if "=" not in raw:
                raise AboxError(
                    f"expected ENV_VAR=docker-secret-name, got {raw!r}"
                )
            env, name = raw.split("=", 1)
            mapping[env.strip()] = name.strip()
        manifest.env_secrets = mapping
        manifest.write(workspace)
        render_mod.write(render_mod.render(manifest, config, workspace, _spec(manifest, config)))

        present = secrets_mod.docker_secret_names()
        for env, name in sorted(mapping.items()):
            mark = "[green]✔[/]" if name in present else "[red]✖ not in the store[/]"
            console.print(f"{mark} {env} ← {name}")
        missing = [n for n in mapping.values() if n not in present]
        if missing:
            console.print(f"  [dim]`abox secrets set {missing[0]}` before running[/]")
        console.print(
            "  [yellow]the agent can read these[/] "
            "[dim]— the egress allowlist is what limits where they can go[/]"
        )
    except AboxError as exc:
        _fail(exc)


@secrets_app.command("detach")
def secrets_detach(
    env: Annotated[list[str], typer.Argument(help="Environment variable names to stop passing.")],
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
) -> None:
    """Stop handing a secret to the agent."""
    try:
        workspace, manifest, config = _load(directory)
        drop = set(env)
        manifest.env_secrets = {
            k: v for k, v in manifest.env_secrets.items() if k not in drop
        }
        manifest.write(workspace)
        render_mod.write(render_mod.render(manifest, config, workspace, _spec(manifest, config)))
        console.print(f"[green]✔[/] no longer passing {', '.join(env)} to the agent")
    except AboxError as exc:
        _fail(exc)


@secrets_app.command("ls")
def secrets_ls(
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show source reference and last sync.")
    ] = False,
    unused: Annotated[
        bool, typer.Option("--unused", help="Only secrets nothing references.")
    ] = False,
) -> None:
    """List secrets in the Docker store and which projects reference them.

    The "used by" column is the reverse index: before rotating or revoking a
    credential, this is the blast radius. It covers every project abox has bound
    to a profile — a project it has never seen cannot appear.
    """
    try:
        config = SecretsConfig.load()
        present = secrets_mod.docker_secret_names()
        state = secrets_mod.SyncState.load()
        cat, _custom = _catalog()
        index = secrets_mod.usage_index(cat)

        names = sorted(present | {m.secret for m in config.mappings} | set(index))
        if unused:
            names = [n for n in names if not index.get(n)]
            if not names:
                console.print("[dim]every stored secret is referenced by a project[/]")
                raise typer.Exit(0)

        table = Table(box=None, pad_edge=False)
        table.add_column("secret", style="bold")
        table.add_column("store")
        table.add_column("source", style="dim")
        if verbose:
            table.add_column("reference", style="dim")
            table.add_column("last sync", style="dim")
        table.add_column("used by")

        for name in names:
            mapping = next((m for m in config.mappings if m.secret == name), None)
            entry = state.entries.get(name, {})
            uses = index.get(name, [])
            if uses:
                used = "\n".join(
                    f"{u.project} → {u.kind} [bold]{u.detail}[/]" for u in uses
                )
            else:
                used = "[dim]— nothing references it[/]"
            row = [
                name,
                "[green]yes[/]" if name in present else "[red]no[/]",
                mapping.kind.value if mapping else entry.get("source", "-"),
            ]
            if verbose:
                row += [
                    mapping.reference if mapping else entry.get("reference", "-"),
                    entry.get("synced_at", "-"),
                ]
            row.append(used)
            table.add_row(*row)
        console.print(table)

        stale = secrets_mod.stale_projects()
        if stale:
            console.print(
                f"\n[yellow]![/] {len(stale)} registered project(s) no longer have a "
                "manifest, so their usage is invisible here:"
            )
            for path in stale[:5]:
                console.print(f"    [dim]{path}[/]")
    except AboxError as exc:
        _fail(exc)


def _print_secret_reports(reports: list[secrets_mod.SecretReport]) -> None:
    table = Table(box=None, pad_edge=False)
    table.add_column("secret", style="bold")
    table.add_column("status")
    table.add_column("source", style="dim")
    table.add_column("detail", style="dim")
    for report in reports:
        colour = "green" if report.ok else "yellow"
        if report.status in (
            secrets_mod.SecretStatus.unreadable,
            secrets_mod.SecretStatus.missing_in_store,
            secrets_mod.SecretStatus.unmapped,
        ):
            colour = "red"
        table.add_row(
            report.name,
            f"[{colour}]{report.status.value}[/]",
            report.source,
            report.detail,
        )
    console.print(table)


# -- gateway --------------------------------------------------------------


@gateway_app.command("up")
def gateway_up(
    profile: Annotated[
        str | None, typer.Argument(help="Profile (default: this project's).")
    ] = None,
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
    force: Annotated[bool, typer.Option("--force", help="Recreate the container.")] = False,
) -> None:
    """Start (or reconcile) a profile's gateway."""
    try:
        name = profile or _load(directory)[1].profile
        config = GlobalConfig.load()
        cat, _custom = _catalog()
        status = gateway.up(name, config, cat, force=force)
        console.print(f"[green]✔[/] {status.container}: {status.detail}")
        console.print(f"  [dim]{status.url}[/]")
        console.print(f"  servers: {', '.join(status.servers) or '(none)'}")
    except AboxError as exc:
        _fail(exc)


@gateway_app.command("down")
def gateway_down(
    profile: Annotated[str | None, typer.Argument()] = None,
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
) -> None:
    """Stop and remove a profile's gateway."""
    try:
        name = profile or _load(directory)[1].profile
        removed = gateway.down(name)
        console.print(
            f"[green]✔[/] {paths.gateway_container(name)} removed"
            if removed
            else f"[dim]{paths.gateway_container(name)} was not running[/]"
        )
    except AboxError as exc:
        _fail(exc)


@gateway_app.command("update")
def gateway_update(
    tag: Annotated[
        str | None,
        typer.Option("--tag", help=f"Tag to resolve (default: {GATEWAY_IMAGE_TAG})."),
    ] = None,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip the confirmation.")] = False,
) -> None:
    """Resolve the gateway tag to a digest and pin it in the global config.

    Pulls the tag first: the digest abox writes is the one the daemon actually
    has, not one asserted by a registry lookup abox would then have to trust
    separately.
    """
    try:
        config = GlobalConfig.load()
        reference = tag or GATEWAY_IMAGE_TAG
        console.print(f"pulling [bold]{reference}[/] …")
        result = dockerx.pull(reference)
        if not result.ok:
            raise AboxError(
                f"could not pull {reference}: {result.stderr.strip()[:200]}",
                hint="check the tag and that the daemon can reach the registry",
            )
        resolved = dockerx.image_digest(reference)
        if not resolved:
            raise AboxError(f"{reference} carries no repo digest to pin")

        current = config.gateway_image
        if current == resolved:
            console.print(f"[green]✔[/] already pinned to {resolved}")
            return

        console.print(f"  [red]- {current}[/]")
        console.print(f"  [green]+ {resolved}[/]")
        if not yes and not typer.confirm(
            "write this digest to the global config?", default=False
        ):
            console.print("[dim]left unchanged[/]")
            return

        config.gateway_image = resolved
        target = config.save()
        console.print(f"[green]✔[/] pinned in {target}")
        console.print(
            "  [dim]`abox gateway up --force` to recreate running gateways from it[/]"
        )
    except AboxError as exc:
        _fail(exc)


@gateway_app.command("status")
def gateway_status(
    profile: Annotated[str | None, typer.Argument()] = None,
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
    tools: Annotated[bool, typer.Option("--tools", help="List the tools it exposes.")] = False,
) -> None:
    """Report gateway health, as seen from the network the agent uses."""
    try:
        config = GlobalConfig.load()
        names = [profile] if profile else sorted(config.profiles)
        for name in names:
            status = gateway.status(name, config)
            colour = "green" if status.ok else ("yellow" if status.running else "red")
            console.print(f"[{colour}]{status.container}[/] — {status.detail}")
            if status.running:
                console.print(f"  url: {status.url}")
                console.print(f"  servers: {', '.join(status.servers) or '(none)'}")
                if status.remote_servers:
                    console.print(
                        f"  remote (proxied): {', '.join(status.remote_servers)}"
                    )
                if status.published_ports:
                    console.print(
                        f"  [bold red]published ports: {', '.join(status.published_ports)}[/]"
                    )
                if tools and status.healthy:
                    registry = gateway.ProfileRegistry.load(name)
                    spec = gateway.build_spec(
                        name,
                        config,
                        servers=registry.servers,
                        remote_servers=registry.remote_servers(),
                    )
                    probe = gateway.probe(spec, want_tools=True)
                    console.print(f"  tools ({len(probe.tools)}): {', '.join(probe.tools) or '-'}")
    except AboxError as exc:
        _fail(exc)


# -- doctor / logs / nuke -------------------------------------------------


@app.command(name="doctor")
def doctor_cmd(
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
    json_out: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show passing checks.")] = False,
    accept_git: Annotated[
        bool, typer.Option("--accept-git", help="Re-baseline the git tamper snapshot.")
    ] = False,
    accept_watch: Annotated[
        bool,
        typer.Option(
            "--accept-watch",
            help="Re-baseline the execution-adjacent file snapshot (mounts.watch).",
        ),
    ] = False,
    quick: Annotated[
        bool, typer.Option("--quick", help="Skip source re-reads for secrets.")
    ] = False,
) -> None:
    """Audit the whole sandbox: config, gateway, secrets, boundaries, egress."""
    try:
        workspace, manifest, config = _load(directory)
        cat, custom = _catalog()
        report = doctor.full(
            manifest,
            config,
            workspace,
            cat,
            custom,
            SecretsConfig.load(),
            accept_git=accept_git,
            accept_watch=accept_watch,
            deep_secrets=not quick,
        )
        if json_out:
            console.print_json(doctor.as_json(report))
            raise typer.Exit(report.exit_code())
        console.print(f"[bold]abox doctor[/] — {workspace}")
        console.print(f"[dim]{doctor.permission_mode_note(manifest)}[/]\n")
        _echo_checks(report, verbose=verbose)
        console.print(f"\n{doctor.summarize(report)}")
        raise typer.Exit(report.exit_code())
    except AboxError as exc:
        _fail(exc)


@app.command()
def logs(
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
    runs: Annotated[bool, typer.Option("--runs", help="Show the run index.")] = False,
    dns: Annotated[bool, typer.Option("--dns", help="Show DNS lookups.")] = False,
    gateway_logs: Annotated[bool, typer.Option("--gateway", help="Tail the gateway log.")] = False,
    transcript: Annotated[
        str | None, typer.Option("--transcript", help="Pretty-print one run's transcript.")
    ] = None,
    limit: Annotated[int, typer.Option("--limit", "-n")] = 20,
) -> None:
    """Read local telemetry: runs, DNS lookups, gateway output, transcripts."""
    try:
        workspace, manifest, config = _load(directory)
        if not any((runs, dns, gateway_logs, transcript)):
            runs = True

        if runs:
            rows = telemetry.runs(workspace, limit=limit)
            if not rows:
                console.print("[dim]no runs recorded yet[/]")
            else:
                table = Table(box=None, pad_edge=False)
                columns = ("run", "when", "mode", "exit", "secs",
                           "denied", "dropped", "session")
                for column in columns:
                    table.add_column(column)
                for row in rows:
                    table.add_row(
                        str(row.get("id", "")),
                        str(row.get("ts", "")),
                        str(row.get("permission_mode", "")),
                        str(row.get("exit_code", "")),
                        f"{row.get('duration_s', 0):.0f}",
                        str(row.get("denied_domains", 0)),
                        str(row.get("dropped_packets", 0)),
                        str(row.get("session_id", ""))[:12],
                    )
                console.print(table)

        if dns:
            rows = telemetry.dns_queries(workspace)[-limit:]
            allow = set(effective_allowlist(manifest, config))
            for row in rows:
                name = str(row.get("name", ""))
                mark = "[green]allowed[/]" if name in allow else "[yellow]denied [/]"
                console.print(f"{mark} {row.get('ts', '')}  {name}  [dim]({row.get('type')})[/]")
            if not rows:
                console.print("[dim]no DNS queries captured yet[/]")

        if gateway_logs:
            container = paths.gateway_container(manifest.profile)
            text = dockerx.logs(container, tail=limit * 5)
            console.print(gateway.sanitize_for_log(text, profile=manifest.profile))

        if transcript:
            path = Path(transcript)
            if not path.is_file():
                matches = sorted(paths.runs_dir(workspace).glob(f"*{transcript}*.jsonl"))
                if not matches:
                    raise AboxError(f"no transcript matching {transcript!r}")
                path = matches[-1]
            console.print(f"[dim]{path}[/]")
            for event in telemetry.iter_transcript(path):
                _print_stream_event(json.dumps(event))
    except AboxError as exc:
        _fail(exc)


@app.command()
def nuke(
    directory: Annotated[Path | None, typer.Option("--dir", "-C")] = None,
    keep_auth: Annotated[
        bool, typer.Option("--keep-auth", help="Never touch the Claude auth volume.")
    ] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Do not prompt.")] = False,
) -> None:
    """Remove containers and generated artifacts for this project."""
    try:
        workspace, manifest, _config = _load(directory)
        if not yes and picker.interactive():
            import questionary

            if not questionary.confirm(
                f"remove abox containers and artifacts for {manifest.project}?", default=False
            ).ask():
                raise typer.Exit(0)

        # Narrowed to this project's label. The sweep used to filter on
        # `managed=true` + `role=agent` alone, so a nuke in one workspace
        # `docker rm -f`'d every other workspace's agent container on the host —
        # including one mid-run, and including a `--keep` container someone was
        # holding open to read after an incident. The prompt above names one
        # project; this is what makes that true.
        for name in dockerx.list_managed(role="agent", project=manifest.project):
            if dockerx.remove(name):
                console.print(f"[green]✔[/] removed container {name}")
        if proxy_mod.down(manifest.project):
            console.print(
                f"[green]✔[/] removed egress proxy {proxy_mod.proxy_container(manifest.project)}"
            )

        registry = gateway.unbind_project(manifest.profile, workspace)
        if not registry.projects:
            if gateway.down(manifest.profile):
                console.print(
                    "[green]✔[/] removed gateway "
                    f"{paths.gateway_container(manifest.profile)}"
                )
        else:
            console.print(
                f"[dim]gateway {paths.gateway_container(manifest.profile)} kept — "
                f"{len(registry.projects)} other project(s) use it[/]"
            )

        removed = render_mod.clean(workspace)
        console.print(f"[green]✔[/] removed {len(removed)} generated artifact(s)")

        # After the containers, so nothing still references them. A teardown that
        # leaves gigabytes of this project's images behind is not a teardown.
        images = dockerx.agent_images(manifest.project)
        reclaimed = sum(img.size for img in images if dockerx.remove_image(img.tag))
        if reclaimed:
            console.print(
                f"[green]✔[/] removed {len(images)} agent image(s), "
                f"{_human_bytes(reclaimed)} reclaimed"
            )

        # Dropped unconditionally, unlike the auth volume: `abox up` rebuilds it
        # in a second, and leaving a bearer token behind on a teardown that the
        # operator asked for would be the wrong default in both directions.
        token_volume = paths.mcp_volume(workspace)
        if dockerx.volume_exists(token_volume):
            dockerx.remove_volume(token_volume)
            console.print(f"[green]✔[/] removed volume {token_volume}")

        volume = paths.claude_volume(workspace)
        if keep_auth or not dockerx.volume_exists(volume):
            console.print(f"[dim]auth volume {volume} kept[/]")
        else:
            drop = yes
            if not yes and picker.interactive():
                import questionary

                drop = bool(
                    questionary.confirm(
                        f"also remove {volume}? this drops the Claude login and session history",
                        default=False,
                    ).ask()
                )
            if drop:
                dockerx.remove_volume(volume)
                console.print(f"[green]✔[/] removed volume {volume}")
            else:
                console.print(f"[dim]auth volume {volume} kept[/]")
    except AboxError as exc:
        _fail(exc)


def main() -> None:
    try:
        app()
    except AboxError as exc:  # pragma: no cover - typer normally handles this
        _fail(exc)


if __name__ == "__main__":  # pragma: no cover
    main()
