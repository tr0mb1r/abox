# abox quickstart

From nothing to a sandboxed agent run. Every command here was executed on a real
machine while writing this; the outputs are what you should actually see.

---

## 0. Host prerequisites

**Docker Desktop** with the MCP Toolkit enabled. That is the whole list.

No npm, no Node, no `@devcontainers/cli`. abox drives the Docker CLI itself and
bakes Claude Code into the agent image from its checksum-verified native binary.

```bash
docker version --format '{{.Server.Version}}'   # daemon reachable?
docker mcp --version                            # MCP Toolkit enabled?
```

If `docker mcp` is not found, open Docker Desktop → Settings → Beta features and
enable **Docker MCP Toolkit**, then restart Docker Desktop.

### Give Docker enough disk

This is the one setting worth checking before you start. The agent image is
~1.3 GB and the base image is ~1 GB, so an 8 GiB Docker disk fills up fast and
you get `no space left on device` in the middle of a build.

```bash
docker run --rm --entrypoint /bin/busybox docker/mcp-gateway:v2 df -h /
```

If `Available` is under ~10 G, raise it: **Docker Desktop → Settings →
Resources → Disk image size**, then Apply & Restart. 40–60 GB is comfortable.

### Optional: 1Password

Only if you want to pull secrets from `op://…` references. Every other secret
source (file, env var, typed at the terminal, already-in-the-store) works
without it, and `abox doctor` will not nag you about a missing `op`.

---

## 1. Install abox

```bash
uv tool install abox-cli
```

The distribution is named `abox-cli` — the bare `abox` name on PyPI belongs to
an unrelated placeholder — but **the command it installs is `abox`**. To track
the repo instead of the last release, use
`uv tool install git+https://github.com/tr0mb1r/abox`.

```bash
abox --version
```

You should get `abox 0.1.4`, from `~/.local/bin/abox`. If the shell can't find
it, add `~/.local/bin` to your `PATH` (or run `uv tool update-shell`).

To upgrade later, re-run the install with `--reinstall`. To remove it:
`uv tool uninstall abox` (uv names the tool after the command, not the
distribution).

Hacking on abox itself? Install the checkout in place instead, from inside it:

```bash
uv tool install --reinstall --force .
```

---

## 2. Set up a project

```bash
cd ~/projects/demo-app
abox init
```

First it asks how you want to start:

- **Quick** — take what abox detected from your repo and go straight to the
  review screen. This is the one to pick.
- **Custom** — answer every question first, then land on the same review screen.

Then you get the review screen, which is where the actual configuring happens:

```
? Review — pick a line to change it:
    gateway profile        default  (port 8811)
    MCP servers            duckduckgo, github-official
    server credentials     1 needed, 0 set here — github.personal_access_token
    tool narrowing         (all tools from every server)
    toolchains             python
    allowed domains        5 + 4 always-on — pypi.org, files.pythonhosted.org…
    masked paths           (2 from global defaults)
    context dirs           (none)
    server network         all 2 on the gateway network (outside the firewall)
    permission mode        default
    claude.ai connectors   off
    transcript format      stream-json
    run timeout            3600s
  ❯ ✔ Save — write agentbox.yaml and render the container
    ✖ Cancel — write nothing
```

Every line is already filled in, and every line is editable: press enter on one,
change it, and you come straight back here. Nothing touches disk until you pick
**Save**, so Cancel really does write nothing — and Ctrl-C inside one question
costs you that answer, not all of them.

Two lines worth knowing about the first time:

- **MCP servers** — type to filter the Docker catalog; entries are grouped by
  whether they need a credential, and each shows whether its image is
  digest-pinned. Pick one that needs a secret and abox offers to store it right
  there, rather than letting `abox up` fail later.
- **allowed domains** — pre-filled from your toolchains and your git remote.
  Everything not on this list is dropped. The handful Claude Code cannot
  authenticate without are always on and are not offered as a choice.
- **server network** — MCP servers run on the gateway's network, which is
  *outside* the agent's firewall. Cutting one off (`none`) is the only per-server
  network limit Docker actually enforces; use it for servers that touch the
  filesystem or the repo, never one that needs the internet.
- **claude.ai connectors** — off, and worth leaving off: on means a second MCP
  path abox does not mediate, whose tool calls never reach the gateway log.

Non-interactive equivalent, useful for scripting:

```bash
abox init --yes --server duckduckgo --profile default
```

This writes `agentbox.yaml` in your repo (commit it) and renders the container
artifacts into abox's own state directory (not your repo).

First run also scaffolds `~/.config/abox/config.yaml`.

---

## 3. Bring it up

```bash
abox up
```

```
✔ network abox-net (created)
✔ gateway abox-gw-default healthy — Docker AI MCP Gateway 2.0.1
   http://abox-gw-default:8811/mcp (servers: none)
✔ artifacts rendered (2 masked path(s))
building agent image…
✔ agent image built: abox-agent-demo-app:3db0abeb6291
```

The first build takes a few minutes (base image pull, toolchains, Claude Code
binary). It is cached afterwards and only rebuilds when the manifest changes.

---

## 4. Log in once

A fresh project has an empty auth volume, so the very first thing to do is an
interactive session:

```bash
abox shell
```

Inside the container, run `claude` and complete the login. It persists in the
per-project volume `abox-claude-<hash>`, so every later headless run reuses it.
Exit the shell and the container is destroyed; the volume stays.

> Skipping this step is the single most common "why did my run exit 1?" — a
> headless run with no login fails at authentication. `abox init` now ends by
> naming this step for exactly that reason.

---

## 5. Run something

```bash
abox run "summarise what this repo does"
```

Each run gets a fresh container, applies the firewall, streams the transcript to
`runs/<ts>-<id>.jsonl`, harvests the DNS log and iptables counters, then destroys
the container. Your workspace and the auth volume persist.

```bash
abox run --continue "now list the risky spots"
abox run --resume <session-id> "and the tests?"
```

---

## 6. Check what happened

```bash
abox doctor
```

The tally line at the bottom reads `<n> ok, <n> warn, 0 fail, <n> skipped`. The
ok/warn/skip counts move with what your project declares; **the number to look
at is `fail`, and on a healthy project it is `0`.**

Warns are not a to-do list. Two of them are standing facts about this design and
will not go away:

- **`agent.auth-credential`** — the Claude OAuth credential lives in the
  per-project `~/.claude` volume, and the agent runs as the user that owns it.
  It can read that credential and send it to any allowed domain. There is no
  setting that removes this; the check exists so it is never silent.
- **`servers.network`** — every MCP server you did *not* pin to `network: none`
  runs on the gateway's network, which is outside the agent's firewall, the SNI
  proxy and the scoped DNS all at once. Expected for a server that needs the
  internet; fix it only for one that does not.

Declare a remote server and you get **`remote.trust`** too — somebody else
operates that endpoint and there is no digest to pin.

What is *not* a warn: **`gateway.image-pinned` is a failure.** The gateway is the
one container that mounts the Docker socket, so a mutable tag there is an offer
to swap the most privileged process in the system, and abox ships that image
digest-pinned by default. If you see it red, run `abox gateway update` — it
resolves the tag and writes the digest back into
`~/.config/abox/config.yaml` for you.

The part worth reading every time is the **egress review queue** — names the
agent looked up that the firewall refused:

```
! egress review queue: 2 domain(s) looked up but not allowed:
    telemetry.vendor.io (x14), pastebin.com (x1)
  ↳ promote deliberately with `abox egress add <domain>`
```

Act on it either way — the queue is only useful while it means *undecided*:

```bash
abox egress add api.example.com          # allow it
abox egress ignore telemetry.vendor.io   # still blocked, stop listing it
```

```bash
abox logs --runs      # run index
abox logs --dns       # every lookup, marked allowed/denied
abox logs --gateway   # gateway container output, tokens redacted
```

Note that **MCP tools are not subject to the agent's firewall**: they execute in
the gateway's server containers. A server like `curl`, `filesystem`, or `docker`
therefore reaches past the agent's egress allowlist and mask overlays by design.
`abox doctor` names those servers so the sandbox never looks tighter than it is.

---

## Adding capability later

**Whatever you already have on this host:**

```bash
abox mcp import          # inventory: what can come in, and what cannot
abox mcp import --apply  # declare the importable ones
abox up
```

Your Docker MCP Toolkit servers come in behind the gateway and keep working with
the secrets already in your Docker store. A local stdio server (a host binary)
cannot cross into the sandbox without mounting it in, and `import` says so rather
than doing it quietly. claude.ai connectors are off by default — see the README
section on them for the two ways to turn them on.

**A container-based MCP server:**

```bash
abox mcp add github-official
abox secrets set github.personal_access_token   # prompted, never echoed
abox up
```

**A hosted MCP server** (Context7, Notion, Asana, Linear — anything internet-hosted).
The gateway proxies it, so the agent gets a tool but no new network path:

```bash
abox mcp add asana                     # already in the catalog as type: remote
abox mcp oauth asana                   # host-side OAuth, token lands in the keychain

abox mcp add-remote context7 --url https://mcp.context7.com/mcp
abox up
abox gateway status --tools            # see exactly what the agent will see
```

**A self-hosted image server, fully local** — e.g. [Serena](https://github.com/oraios/serena)
(semantic code tools). It runs as a container behind the gateway. Custom images
are normally digest-pinned; to avoid pushing a build to a registry just to pin
it, set `pin: false` and abox runs your local tag on trust — it won't try to
pull it, and the gateway never signature-checks images outside `docker.io/mcp/*`:

```bash
git clone https://github.com/oraios/serena && cd serena
docker build -t serena:local .
```

```yaml
# ~/.config/abox/custom-servers.yaml   — a bare name -> server mapping
serena:
  image: serena:local
  pin: false                 # trust this local build; abox will not pull it
  env: { SERENA_DOCKER: "1" }
  volumes:
    - /abs/path/to/project:/workspace/project    # Serena needs the code
  command: [serena, start-mcp-server, --transport, stdio,
            --context, claude-code, --project, /workspace/project]
```

```bash
abox mcp add serena && abox up
```

`doctor` flags it two ways, both true: an unpinned local image (no digest, no
signature — the trust is yours), and a boundary-spanning server (it runs in the
gateway's container with read-write access to the mounted code, outside the
agent's firewall). The stock image bakes Node and Rust language servers, not Go.

**A secret the agent's own work needs** (not an MCP server — the agent itself):

```bash
abox secrets set database.url                  # prompted; or --file / --env / --stdin
abox secrets attach DATABASE_URL=database.url  # now in the agent's environment
abox up
```

abox passes a reference the Docker daemon resolves, so no plaintext lands in any
file abox writes. But the agent *can* read it — that is the point — so `doctor`
flags it every run and the egress allowlist becomes the real boundary.

**Domain-level egress** (stop domain fronting via shared CDN addresses):

```yaml
# ~/.config/abox/config.yaml
egress_proxy:
  enabled: true
```

Every outbound 443 connection is then filtered by TLS server name at an nginx
container, not by IP — so an allowed address carrying a forged SNI is refused.
`abox up` starts it; `abox doctor` shows what it turned away.

**A domain the agent needs:**

```bash
abox egress add api.example.com
```

Takes effect on the next run, since every run gets a fresh container.

---

## Turning on `bypassPermissions`

Set it in `agentbox.yaml` when you want unattended runs:

```yaml
run:
  permission_mode: bypassPermissions
```

abox then **refuses to run** unless every boundary check passes — caps present,
no docker socket, no published ports, artifacts unmodified, firewall live inside
the container. Check first:

```bash
abox doctor
```

---

## Tearing down

```bash
abox nuke              # containers, images + generated artifacts; prompts before the auth volume
abox nuke --keep-auth  # keep the Claude login
```

The gateway survives if another project still uses its profile.

### Disk

The agent image tag is content-addressed — `abox-agent-<project>:<manifest-digest>`
— so every change to `agentbox.yaml` builds a *new* image. `abox up` removes the
ones it supersedes once the replacement has built, and says what it reclaimed:

```
✔ agent image built: abox-agent-demo-app:3db0abeb6291
✔ reclaimed 1.4 GB (1 superseded image)
```

`abox doctor` reports what this project's images occupy, and flags anything
still reclaimable — an image pinned by a running container at prune time, or a
project not brought up since it was last edited. `abox nuke` removes all of
them.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `no space left on device` mid-build | Docker disk image full | `abox doctor` reports this project's images; raise the disk in Settings → Resources, `abox nuke` a project you are done with, or `docker image prune` |
| `abox run` exits 1 immediately | no Claude login in the volume | `abox shell`, run `claude`, log in |
| `gateway abox-gw-<p> is running: not created` | gateway never started | `abox up` (or `abox gateway up`) |
| `could not pull MCP server image` | the gateway starts servers with `--pull never` | abox pre-pulls; a failure here is a real registry/disk problem |
| `mounted artifacts are unmodified: ✖` | something edited the files abox mounts | `abox up` to re-render, then find out who |
| `git config unchanged: ✖ added core.hookspath` | a hook or alias appeared | review it, then `abox doctor --accept-git` to re-baseline |
| doctor warns about a mask | a new file matches a mask glob but isn't covered | `abox up` to re-render the overlays |
| `artifacts match the manifest: manifest changed` | you edited `agentbox.yaml`, or abox's defaults moved | `abox up` |
| a domain keeps reappearing in the queue | you have decided against it but not recorded that | `abox egress ignore <domain>` |
| my usual MCP servers are missing inside the sandbox | a project starts with none declared | `abox mcp import` |
| my claude.ai connectors are missing | off by default; they are a second, unmediated MCP path | `abox mcp add <name>` if the catalog has it, else `run.connectors: true` |

---

## Where things live

```
<your repo>/
  agentbox.yaml          commit this — it is the sandbox declaration
  .devcontainer/         review copy; abox never reads it back

~/.config/abox/
  config.yaml            network, gateway image, profiles, defaults
  secrets.yaml           source → docker secret name (references, never values)
  custom-servers.yaml    servers outside the Docker catalog

~/.local/state/abox/
  gateways/              per-profile token, registry, generated remote catalog
  <project-hash>/
    artifacts/           runspec.json (the literal docker argv), Dockerfile,
                         init-firewall.sh, mcp.json — mounted read-only
    runs/                one JSONL transcript per run
    runs.jsonl           run index
    dns-queries.jsonl    every name the agent looked up
```

The artifacts abox mounts live **outside** your repo on purpose: an agent that
rewrites the firewall script in the workspace changes nothing except a `doctor`
finding.
