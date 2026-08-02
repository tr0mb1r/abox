# Changelog

Notable changes per release. Security fixes say what was reachable before the
fix, because "hardening" is not a description anyone can act on.

## 0.1.5 (unreleased)

The bulk of this release came out of a full-codebase review. Most of it is one
shape repeated: a control that was real, and a check that could not observe it
failing. `abox doctor` is the product's claim about itself, so a check that
cannot go red is worse than no check at all — it converts an absent control into
a reassuring line of output.

### Breaking

Read this section before upgrading. Each of these will stop something that
worked in 0.1.4.

- **`network: bridge` (or `host`, `none`, `default`, `container:…`) in
  `config.yaml` now refuses to load.** abox execs `init-firewall.sh` as root
  with `NET_ADMIN`, so on a shared namespace those rules land outside the
  sandbox — on `host` they rewrite your own netfilter tables. Set `network` to a
  user-defined bridge; the default `abox-net` is one.
- **`remote_user: root` (or `0`, or either with a `:group` suffix) now refuses
  to load.** Root plus `NET_ADMIN` can flush the firewall, kill the resolver,
  truncate the DNS log and forge the `firewall-ok` marker that gates
  `bypassPermissions` — the agent authoring its own evidence.
- **`abox nuke --yes` no longer deletes the Claude auth volume.** It previously
  did, while the interactive default was to keep it, so a cleanup script silently
  dropped your login and session history. Pass `--drop-auth` if you want the old
  behaviour.
- **`abox shell` now refuses a container that did not report a working
  firewall,** matching `abox run`. Use `--allow-broken-firewall` to proceed; it
  says on exit that the session had unrestricted egress, and records it.
- **`.gitattributes` joins the default `mounts.watch` list.** It is the other
  half of a git filter attack — `.git/config` names the command, `.gitattributes`
  picks the files. This changes the manifest digest, so every project rebuilds
  its agent image on the next `abox up`.
- **`tools: []` in `custom-servers.yaml` is now rejected** rather than silently
  meaning "every tool". Write `tools: ['*']` for all, or name the tools. An
  invalid entry is skipped and named instead of failing the whole file, so one
  stale server no longer breaks unrelated projects.
- **`abox egress ignore` refuses a host that is allowlisted unconditionally.**
  It used to accept it and print "still blocked" about a host the firewall went
  on allowing.

### Security

- **`.git/config` is fingerprinted key by key.** The previous check listed five
  dangerous keys and so missed `core.pager`, `core.fsmonitor`, `core.sshCommand`,
  `core.editor`, `filter.*.clean`, `diff.*.textconv` and `url.*.insteadOf`. Every
  one of those runs a command of the agent's choosing on the **host**, on an
  ordinary `git log` — and the agent can write `.git/config`, because
  `/workspace` is a live read-write bind. The rule is inverted now: everything
  not on a benign-by-construction list is watched.
- **`boundary.artifacts-private` can fail.** Its callers reached it through a
  helper that re-applied `0755` as a side effect of returning the path, so the
  mode was repaired seconds before the stat and the check reported the tampering
  it had just undone.
- **The `network` boundary check asserts a property.** It compared the config to
  a runspec rendered from that same config — a tautology that passed for
  `--network host`.
- **The agent's uid is checked.** Nothing verified it; the one test that looked
  like it did compared the rendered argv to the value that produced it.
- **Agent text is escaped before printing.** Claude's output reached a
  markup-enabled console unescaped, so a message mentioning `[/etc/hosts]` raised
  an error mid-run — and, unescaped, agent text could style itself or forge a
  line that read as abox's own.
- **An imported catalog file can no longer silently redefine an official
  server.** Files under `~/.docker/mcp/catalogs/` merge in filename order, last
  one wins, and `docker mcp catalog import` writes there. A digest proves an
  image cannot change under you; it says nothing about whose image it was.
  `doctor` fails when a declared server is defined more than once.
- **Tool narrowing that a shared gateway cannot enforce is now reported.** One
  gateway serves every project on a profile and takes one `--tools=` list, so a
  co-tenant project declaring the same server unfiltered dropped your filter
  entirely. The union still wins — intersecting would strip tools from a project
  that never asked — but `doctor` fails and names the project that widened it.
- **Mask overlays are gated, not merely warned about.** A file that started
  matching `.env*` after the last `abox up` got no overlay, under a guarantee
  the docs state flatly.
- **The firewall certifies its resolver.** `setup_dns || true` discarded its own
  failure and no self-test covered DNS, so with dnsmasq absent the container kept
  Docker's embedded resolver — which this firewall permits — and resolved
  anything at all while the run recorded `denied_domains=0`.
- **The SNI proxy image can be digest-pinned and is checked.** It is the sole
  arbiter of the allowlist when enabled, and it defaulted to a mutable tag.

### Fixed

- `abox up` no longer deletes another workspace's agent images. Tags are
  `abox-agent-<project>` and project defaults to the directory name, so two
  workspaces with the same name deleted each other's images on every `up`.
- The streaming runner's timeout works. It could not fire on a child that
  stalled without printing, and stderr was drained only after stdout hit EOF, so
  a command writing more than one pipe buffer to stderr deadlocked with no
  deadline to break it. `run.timeout` was unenforceable for exactly this reason.
- A timed-out command kills its process group, so grandchildren holding the
  pipes die with it. Found on Linux, where `sh -c` forks rather than execs.
- `abox nuke` sweeps only its own project's containers. It removed every abox
  agent container on the host, including one mid-run.
- `claude` reads its MCP config from `/run/abox/mcp.json`, the path every other
  artifact already named. On a host whose uid is not 1000 the agent got `EACCES`
  on a file `doctor` reported as correctly staged.
- `abox mcp rm` no longer raises an uncaught validation error, and
  `abox secrets rm` no longer exits 0 when the store refused the removal.
- `secrets sync --dry-run` reads the real store instead of assuming an empty
  one; a partial sync no longer discards the digests it had already written.
- `abox secrets rm` warns when the secret is still mapped in `secrets.yaml`,
  where the next sync would push it straight back.
- The `abox init` review screen stops discarding answers: tool narrowing
  survives, mask globs with spaces survive, a previously-ignored egress domain
  no longer aborts the whole init at Save.
- `abox logs --runs` shows `?` rather than `0` when the firewall counters could
  not be read. A zero is a claim about the firewall; a failed read is a claim
  about nothing.

### Changed

- `abox init` is a review-and-edit screen rather than a linear interrogation.
- Docs no longer say abox has never run on Linux. It runs there in CI on every
  change — and Linux is where several of the defects above were found, after
  passing on Docker Desktop for months.

## 0.1.4

Fixes the `abox shell` banner, which greeted every session in 0.1.3 with two
`bash: claude\: command not found` errors before printing a mangled version of
its own message.
