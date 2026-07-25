"""Local, file-based telemetry: run transcripts, DNS queries, firewall counters.

Everything abox knows about a run lands under
``~/.local/state/abox/<project-hash>/`` as JSONL. No daemon, no database, no
network. ``abox doctor`` reads the same files to build the egress review queue —
"the agent asked for this name and the firewall refused" is the single most
useful signal this design produces, and it only exists because dnsmasq logs
every lookup including the ones that go nowhere.
"""

from __future__ import annotations

import json
import re
import time
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from . import paths

RUNS_INDEX = "runs.jsonl"
DNS_QUERIES = "dns-queries.jsonl"
FW_COUNTERS = "fw-counters.json"

#: `query[A] api.anthropic.com from 172.18.0.3`
_DNS_QUERY_RE = re.compile(
    r"query\[(?P<qtype>[A-Z]+)\]\s+(?P<name>\S+)\s+from\s+(?P<client>\S+)"
)
#: `reply api.anthropic.com is 160.79.104.10` / `... is NXDOMAIN`
_DNS_REPLY_RE = re.compile(r"reply\s+(?P<name>\S+)\s+is\s+(?P<answer>\S+)")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")
    path.chmod(0o600)


def read_jsonl(path: Path, *, limit: int | None = None) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows[-limit:] if limit else rows


# -- run index ------------------------------------------------------------


@dataclass
class RunRecord:
    """One row in ``runs.jsonl``. Prompts are stored by digest, never verbatim."""

    id: str
    ts: str
    project: str
    profile: str
    prompt_sha: str
    duration_s: float
    exit_code: int
    session_id: str = ""
    container: str = ""
    transcript: str = ""
    permission_mode: str = ""
    servers: list[str] = field(default_factory=list)
    denied_domains: int = 0
    dropped_packets: int = 0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def record_run(workspace: Path, record: RunRecord) -> Path:
    path = paths.project_state_dir(workspace) / RUNS_INDEX
    append_jsonl(path, record.to_dict())
    return path


def runs(workspace: Path, *, limit: int | None = None) -> list[dict[str, Any]]:
    return read_jsonl(paths.project_state_dir(workspace) / RUNS_INDEX, limit=limit)


def transcript_path(workspace: Path, run_id: str, ts: str) -> Path:
    safe_ts = ts.replace(":", "").replace("-", "")
    return paths.runs_dir(workspace) / f"{safe_ts}-{run_id}.jsonl"


def new_run_id() -> str:
    import secrets as pysecrets

    return pysecrets.token_hex(4)


def prompt_digest(prompt: str) -> str:
    import hashlib

    return hashlib.sha256(prompt.encode()).hexdigest()[:16]


# -- dnsmasq --------------------------------------------------------------


@dataclass(frozen=True)
class DnsQuery:
    name: str
    qtype: str
    client: str
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.qtype, "client": self.client}


def parse_dns_log(text: str) -> list[DnsQuery]:
    out: list[DnsQuery] = []
    for line in text.splitlines():
        match = _DNS_QUERY_RE.search(line)
        if not match:
            continue
        out.append(
            DnsQuery(
                name=match.group("name").rstrip(".").lower(),
                qtype=match.group("qtype"),
                client=match.group("client"),
                raw=line.strip(),
            )
        )
    return out


def parse_dns_answers(text: str) -> dict[str, set[str]]:
    """name -> answers seen. ``NXDOMAIN``/``<CNAME>`` land here verbatim."""
    answers: dict[str, set[str]] = {}
    for line in text.splitlines():
        match = _DNS_REPLY_RE.search(line)
        if not match:
            continue
        name = match.group("name").rstrip(".").lower()
        answers.setdefault(name, set()).add(match.group("answer"))
    return answers


def collect_dns(workspace: Path, run_id: str, *, log: Path | None = None) -> list[DnsQuery]:
    """Fold this run's dnsmasq log into the per-project query stream."""
    source = log or (paths.current_run_dir(workspace) / "dns.log")
    if not source.is_file():
        return []
    text = source.read_text(encoding="utf-8", errors="replace")
    queries = parse_dns_log(text)
    target = paths.project_state_dir(workspace) / DNS_QUERIES
    ts = _now()
    for query in queries:
        append_jsonl(target, {"ts": ts, "run": run_id, **query.to_dict()})
    return queries


def dns_queries(workspace: Path) -> list[dict[str, Any]]:
    return read_jsonl(paths.project_state_dir(workspace) / DNS_QUERIES)


# -- iptables counters ----------------------------------------------------


@dataclass
class FirewallCounters:
    dropped_packets: int = 0
    dropped_bytes: int = 0
    accepted_packets: int = 0
    rules: list[dict[str, Any]] = field(default_factory=list)
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "dropped_packets": self.dropped_packets,
            "dropped_bytes": self.dropped_bytes,
            "accepted_packets": self.accepted_packets,
            "rules": self.rules,
        }


def parse_iptables_counters(text: str) -> FirewallCounters:
    """Parse ``iptables -L OUTPUT -v -x -n``.

    Only the OUTPUT chain matters: the terminal DROP rule's packet count is the
    number of egress attempts the sandbox refused.
    """
    counters = FirewallCounters(raw=text)
    in_output = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Chain "):
            in_output = stripped.startswith("Chain OUTPUT")
            continue
        if not in_output or not stripped or stripped.startswith("pkts"):
            continue
        parts = stripped.split(None, 3)
        if len(parts) < 3 or not parts[0].isdigit():
            continue
        pkts, byts, target = int(parts[0]), int(parts[1]), parts[2]
        rest = parts[3] if len(parts) > 3 else ""
        counters.rules.append(
            {"packets": pkts, "bytes": byts, "target": target, "spec": rest.strip()}
        )
        if target == "DROP":
            counters.dropped_packets += pkts
            counters.dropped_bytes += byts
        elif target == "ACCEPT":
            counters.accepted_packets += pkts
    return counters


def record_counters(workspace: Path, run_id: str, counters: FirewallCounters) -> Path:
    path = paths.project_state_dir(workspace) / FW_COUNTERS
    history: dict[str, Any] = {}
    if path.is_file():
        try:
            history = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            history = {}
    runs_map = history.setdefault("runs", {})
    runs_map[run_id] = {"ts": _now(), **counters.to_dict()}
    # Keep the file bounded; the transcripts carry the detail.
    if len(runs_map) > 200:
        for key in sorted(runs_map)[: len(runs_map) - 200]:
            runs_map.pop(key, None)
    path.write_text(json.dumps(history, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def counters(workspace: Path) -> dict[str, Any]:
    path = paths.project_state_dir(workspace) / FW_COUNTERS
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


# -- egress review queue --------------------------------------------------


@dataclass(frozen=True)
class DeniedDomain:
    name: str
    count: int
    runs: int
    last_seen: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _domain_allowed(name: str, allowlist: Iterable[str]) -> bool:
    """A name is covered when it is in the allowlist verbatim.

    Suffix matching is deliberately *not* used: the firewall resolves exact
    names into the ipset, so ``cdn.example.com`` being allowed says nothing
    about ``evil.example.com``. Treating it as covered here would hide the very
    lookups this queue exists to surface.
    """
    return name.lower() in {a.lower() for a in allowlist}


def review_queue(
    workspace: Path,
    allowlist: Iterable[str],
    *,
    since_run: str | None = None,
    ignored: Iterable[str] = (),
) -> list[DeniedDomain]:
    """Domains the agent looked up that the firewall would not route.

    ``allowlist`` must include the gateway's container name: the firewall opens
    a hole for it, so reporting it as denied would be a standing false positive
    that trains the reader to ignore this list.
    """
    rows = dns_queries(workspace)
    if since_run:
        seen_from = False
        filtered = []
        for row in rows:
            if row.get("run") == since_run:
                seen_from = True
            if seen_from:
                filtered.append(row)
        rows = filtered

    allow = [*allowlist, *ignored]
    counts: Counter[str] = Counter()
    run_sets: dict[str, set[str]] = {}
    last_seen: dict[str, str] = {}
    for row in rows:
        name = str(row.get("name") or "").lower()
        if not name or _domain_allowed(name, allow):
            continue
        counts[name] += 1
        run_sets.setdefault(name, set()).add(str(row.get("run") or ""))
        last_seen[name] = str(row.get("ts") or "")

    return [
        DeniedDomain(
            name=name,
            count=count,
            runs=len(run_sets.get(name, set())),
            last_seen=last_seen.get(name, ""),
        )
        for name, count in counts.most_common()
    ]


def iter_transcript(path: Path) -> Iterator[dict[str, Any]]:
    if not path.is_file():
        return
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def session_id_from_transcript(path: Path) -> str:
    """Claude's stream-json emits ``session_id`` on the init event."""
    for event in iter_transcript(path):
        session = event.get("session_id")
        if session:
            return str(session)
    return ""


def tool_calls_from_transcript(path: Path) -> list[str]:
    names: list[str] = []
    for event in iter_transcript(path):
        message = event.get("message") or {}
        for block in message.get("content") or []:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                name = block.get("name")
                if name:
                    names.append(str(name))
    return names


def reset_current_run(workspace: Path) -> Path:
    """Clear the per-run bind-mount directory so telemetry is run-scoped."""
    directory = paths.current_run_dir(workspace)
    directory.mkdir(parents=True, exist_ok=True)
    for path in directory.iterdir():
        if path.is_file():
            path.unlink()
    # Only abox writes here now — the container's logs are harvested out at
    # teardown rather than shared through a mount the agent could write to.
    directory.chmod(0o700)
    return directory
