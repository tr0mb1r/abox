# Security

abox limits the blast radius of an agent that has been made hostile. This
document says what has actually been tested, what has not, and where the
controls stop.

For the adversary model, the non-goals and the residual-risk list, see
[Threat model](README.md#threat-model). This file is the evidence.

## Maturity

**abox has not had third-party security review.** Version 0.1.0. One author. The
tests below were written by the same person who wrote the code they test, which
is worth exactly as much as that usually is. Adopt accordingly: it is a
defence-in-depth layer over Docker, not a security boundary anyone else has
audited.

If you do review it, the findings are welcome and will be published here whether
or not they are flattering — the residual-risk table exists because a previous
review produced it.

## Reporting a vulnerability

Report through **GitHub private security advisories**:
[open an advisory on tr0mb1r/abox](https://github.com/tr0mb1r/abox/security/advisories/new).
That is the only channel — it keeps the report private until there is a fix, and
it is the one place a report will be seen.

Please include what you were able to reach, from which position (agent
container, MCP server container, host), and the `abox doctor` output if it is
relevant. There is no bounty and no SLA; this is a personal project. Expect a
reply within a week.

Do not open a public issue for anything that lets a sandboxed agent reach the
host.

## Tested attacks

Every row names the test that proves it. Rows whose result is **succeeds** are
here on purpose — a matrix that only lists wins is marketing.

Tests marked *(docker)* need a live Docker daemon and are deselected by default:

```bash
uv run pytest -m docker          # the ones that build images and run containers
uv run pytest                    # everything else, no daemon needed
```

Rows marked *(manual)* were measured by hand and written up in `docs/notes/`;
they have no automated test, and saying so is the point.

### Egress

| Attack | Control | Result | Test |
|---|---|---|---|
| Domain fronting via a shared CDN address — allowed IP, forged server name | SNI proxy reads the TLS ClientHello | **refused**, and the attempted name is logged | `tests/test_integration_docker.py::test_domain_fronting_is_refused` *(docker)* |
| TLS with no SNI at all, forged `Host:` header, straight to an allowed IP | SNI proxy has no name to match, fails closed | **refused** | `tests/test_integration_docker.py::test_no_sni_connection_is_refused` *(docker)* |
| Reach a host nobody allowlisted | default-deny iptables + ipset | **refused** | `tests/test_integration_docker.py::test_default_deny_egress` *(docker)* |
| Exfiltrate via DNS query names | dnsmasq scoped to the allowlist | **NXDOMAIN**, and the refused lookup is still logged | `tests/test_integration_docker.py::test_dns_resolution_is_scoped_to_the_allowlist` *(docker)* |
| Downgrade to plaintext on port 80 | `egress_ports: [443]` by default | **refused** unless 80 is opted in | `tests/test_render.py::test_port_80_is_opt_in` |
| Reach the agent, gateway or proxy from the host network | nothing is published | **no port bindings exist** | `test_gateway_publishes_nothing_to_the_host`, `test_the_proxy_publishes_nothing` *(docker)* |
| Allowlist `pypi.org`, reach everything else on those Fastly addresses | ipset matches IPs, not names | **succeeds in ipset mode** — the SNI proxy is the fix; doctor names the shared addresses either way | `tests/test_runner_and_doctor.py` → `egress.shared-addresses` |

### Execution and privilege

| Attack | Control | Result | Test |
|---|---|---|---|
| Escalate to root via `sudo` | `sudo` purged from the image; the build asserts its absence | **build fails** if present; `sudo` fails at runtime | `tests/test_render.py::test_dockerfile_purges_sudo`, `test_sudo_is_absent_from_the_image`, `test_agent_cannot_become_root` *(docker)* |
| Reach the Docker daemon from the agent | no socket bind in the runspec | **no socket to open** | `tests/test_integration_docker.py::test_agent_cannot_reach_the_docker_socket` *(docker)* |
| Let the firewall silently fail and run anyway | the script writes a marker abox reads back through the socket | **no marker, no agent** | `tests/test_integration_docker.py::test_firewall_marker_proves_the_rules_are_live` *(docker)* |
| Reach the gateway's MCP endpoint without the token | bearer auth on TCP transports | **401** | `tests/test_integration_docker.py::test_probe_is_rejected_without_the_token` *(docker)* |

### Filesystem and tampering

| Attack | Control | Result | Test |
|---|---|---|---|
| Read a masked file (`.env`, `secrets/`) | empty overlay mounted over the path | **empty inside**, untouched on the host | `tests/test_integration_docker.py::test_masked_file_is_empty_inside_the_container` *(docker)* |
| Edit the firewall script to widen the allowlist | authoritative artifacts live outside the workspace, mounted read-only | **no effect**, and drift is a doctor finding | `tests/test_render.py::test_authoritative_artifacts_live_outside_the_workspace`, `test_drift_detects_a_tampered_mounted_artifact` |
| Truncate `dns.log` to erase the egress review queue | log dir is container-internal and root-owned, never bind-mounted | **not writable** | `tests/test_integration_docker.py::test_the_agent_cannot_edit_its_own_audit_trail` *(docker)* |
| Plant a git hook or `core.hooksPath` alias | `.git/hooks` masked by default; `.git/config` fingerprinted | **doctor fails** | `tests/test_runner_and_doctor.py::test_git_tamper_notices_a_planted_hook` |
| Poison `.github/workflows/ci.yml` so it runs on the CI runner | watched, not masked — fingerprinted into `git-snapshot.json` | **succeeds; doctor names the file afterwards.** Not prevented: masking the class would break ordinary work | `tests/test_runner_and_doctor.py::test_exec_surface_baselines_then_flags_a_poisoned_workflow` |
| Repoint a watched file's symlink at identical content | symlinks recorded by target, not followed | **detected** | `tests/test_runner_and_doctor.py::test_exec_surface_records_a_symlink_by_its_target_not_its_contents` |

### Supply chain

| Attack | Control | Result | Test |
|---|---|---|---|
| Move the `:v2` tag under the gateway | gateway image digest-pinned; the running container is compared to the pin | **doctor fails** | `tests/test_runner_and_doctor.py::test_running_gateway_on_a_different_digest_fails`, `test_unpinned_gateway_image_is_a_failure` |
| Ship an MCP server image on a mutable tag | catalog and custom images must be digest-pinned | **doctor fails**, unless `pin: false` is set deliberately (reported separately) | `tests/test_runner_and_doctor.py::test_pin_false_does_not_fail_the_pinning_check` |
| Substitute a custom image the gateway will not signature-check | the digest is the only anchor — the gateway signs only `docker.io/mcp/*` | **not defended for out-of-namespace images.** doctor states this rather than implying signatures cover them | `tests/test_remote_servers.py::test_doctor_names_the_custom_image_trust_story` |
| Install a malicious package from an allowlisted registry | none — see non-goals | **succeeds** | — |

### Network position

| Attack | Control | Result | Test |
|---|---|---|---|
| Agent A reaches agent B on a shared profile | A's `OUTPUT DROP`; B's `INPUT DROP` as a second layer | **blocked**, by A's OUTPUT first | *(manual)* [`docs/notes/network-segmentation.md`](https://github.com/tr0mb1r/abox/blob/main/docs/notes/network-segmentation.md) |
| Agent A relays through project B's SNI proxy | A's `OUTPUT DROP` permits only its own proxy; `:443` is DNAT'd there | **blocked** | *(manual)* [`docs/notes/network-segmentation.md`](https://github.com/tr0mb1r/abox/blob/main/docs/notes/network-segmentation.md) |
| An MCP server container reaches an arbitrary host on the agent's behalf | none — server containers are outside the firewall, the SNI proxy and the scoped resolver at once | **succeeds.** `server_network: none` closes it for servers that do not need the internet; nothing closes it for ones that do | *(manual)* [`docs/notes/mcp-egress-investigation.md`](https://github.com/tr0mb1r/abox/blob/main/docs/notes/mcp-egress-investigation.md) |
| An MCP server container relays through any project's SNI proxy | none — nginx has no source restriction on the bridge | **succeeds.** It already has unrestricted egress, so this grants no new reach; it does mean the allowlist is not a boundary for it | *(manual)* [`docs/notes/network-segmentation.md`](https://github.com/tr0mb1r/abox/blob/main/docs/notes/network-segmentation.md) |
| Isolate a server from the network entirely | `server_network: none` → `disableNetwork` → `docker run --network none` | **enforced by Docker.** Verified live: `git` and `serena` spawn with `--network none`, and Serena still serves all its tools | `tests/test_remote_servers.py::test_catalog_server_is_shadowed_verbatim_plus_disable_network` |

### Credentials

| Attack | Control | Result | Test |
|---|---|---|---|
| Read a secret abox routed to an MCP server | the daemon injects `se://` references into the server container; neither gateway nor agent holds a value | **not reachable from the agent** | `tests/test_secrets.py::test_env_secrets_reach_the_runspec_as_references_not_values` |
| Exfiltrate a secret from `secrets attach` to an allowed domain | none — this is the documented weakening | **succeeds.** The egress allowlist is the boundary, and doctor says so every run | `tests/test_runner_and_doctor.py` → `agent.env-secrets` |
| Exfiltrate the Claude OAuth credential from `~/.claude` | none — the agent must be able to read it | **succeeds.** Bounded only by the per-project volume and the allowlist; `run.connectors: true` removes the bound | `tests/test_runner_and_doctor.py::test_auth_credential_is_reported_even_with_no_attached_secrets` |
| Reach the host Docker daemon through a crafted MCP request | none — the gateway is trusted third-party code that mounts the socket | **untested and undefended.** abox pins the gateway by digest; it cannot audit it | — |

## What is not tested

Named so the matrix is not read as complete:

- **The gateway's own request handling.** It is third-party code holding the
  Docker socket. abox pins its digest and checks the running container against
  the pin. Nothing here fuzzes it.
- **Container escape.** Out of scope; see non-goals.
- **Bearer-token theft and replay.** The 401 path is tested; extracting a live
  token from a running agent and replaying it is not.
- **Bridge-level attacks** (ARP spoofing, MAC flooding). Docker bridge networks
  do not isolate at L2 and abox does not add anything that would.
- **The gateway spawning a container outside the intended set.** If a compromised
  agent could induce that, the container would land on the bridge unfirewalled.
  Not attempted.
- **macOS-only.** Every result above was measured on Docker Desktop for macOS.
  Linux behaviour differs in at least one relevant way — bind-mount uid/mode
  *are* enforced there — and has not been measured.
