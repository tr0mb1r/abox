"""Telemetry parsing: dnsmasq, iptables counters, transcripts, review queue."""

from __future__ import annotations

import json
from pathlib import Path

from abox import paths, telemetry

DNS_LOG = """
Jul 23 20:10:11 dnsmasq[12]: query[A] api.anthropic.com from 172.18.0.3
Jul 23 20:10:11 dnsmasq[12]: forwarded api.anthropic.com to 127.0.0.11
Jul 23 20:10:11 dnsmasq[12]: reply api.anthropic.com is 160.79.104.10
Jul 23 20:10:14 dnsmasq[12]: query[AAAA] pastebin.com from 172.18.0.3
Jul 23 20:10:14 dnsmasq[12]: reply pastebin.com is NXDOMAIN
Jul 23 20:10:15 dnsmasq[12]: query[A] Telemetry.Example.COM. from 172.18.0.3
"""

IPTABLES = """
Chain INPUT (policy DROP 3 packets, 180 bytes)
    pkts      bytes target     prot opt in     out     source               destination
      12      900 ACCEPT     all  --  lo     *       0.0.0.0/0            0.0.0.0/0

Chain OUTPUT (policy DROP 0 packets, 0 bytes)
    pkts      bytes target     prot opt in     out     source               destination
      40     3200 ACCEPT     all  --  *      lo      0.0.0.0/0            0.0.0.0/0
     118    14000 ACCEPT     tcp  --  *      *       0.0.0.0/0            172.18.0.2  tcp dpt:8811
       7      420 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0   /* drop */
"""


def test_parse_dns_log_extracts_queries() -> None:
    queries = telemetry.parse_dns_log(DNS_LOG)
    names = [q.name for q in queries]
    assert names == ["api.anthropic.com", "pastebin.com", "telemetry.example.com"]
    assert queries[1].qtype == "AAAA"
    assert queries[0].client == "172.18.0.3"


def test_parse_dns_answers() -> None:
    answers = telemetry.parse_dns_answers(DNS_LOG)
    assert answers["api.anthropic.com"] == {"160.79.104.10"}
    assert answers["pastebin.com"] == {"NXDOMAIN"}


def test_parse_iptables_counts_only_the_output_chain() -> None:
    counters = telemetry.parse_iptables_counters(IPTABLES)
    assert counters.dropped_packets == 7
    assert counters.dropped_bytes == 420
    assert counters.accepted_packets == 158  # 40 + 118, not the INPUT chain's 12


def test_parse_iptables_keeps_rule_detail() -> None:
    counters = telemetry.parse_iptables_counters(IPTABLES)
    assert any("8811" in rule["spec"] for rule in counters.rules)


def test_collect_dns_folds_into_the_project_stream(workspace: Path) -> None:
    paths.ensure_project_state(workspace)
    (paths.current_run_dir(workspace) / "dns.log").write_text(DNS_LOG)
    queries = telemetry.collect_dns(workspace, "run1")
    assert len(queries) == 3
    rows = telemetry.dns_queries(workspace)
    assert {row["run"] for row in rows} == {"run1"}


def test_review_queue_lists_denied_names_with_counts(workspace: Path) -> None:
    paths.ensure_project_state(workspace)
    (paths.current_run_dir(workspace) / "dns.log").write_text(DNS_LOG + DNS_LOG)
    telemetry.collect_dns(workspace, "run1")
    denied = telemetry.review_queue(workspace, ["api.anthropic.com"])
    names = {d.name: d.count for d in denied}
    assert names == {"pastebin.com": 2, "telemetry.example.com": 2}


def test_review_queue_does_not_treat_a_parent_domain_as_coverage(workspace: Path) -> None:
    """Allowing example.com must not silently cover evil.example.com: the
    firewall resolves exact names, so suffix matching here would hide exactly
    the lookups this queue exists to surface."""
    paths.ensure_project_state(workspace)
    (paths.current_run_dir(workspace) / "dns.log").write_text(
        "Jul 23 20:10:15 dnsmasq[1]: query[A] evil.example.com from 172.18.0.3\n"
    )
    telemetry.collect_dns(workspace, "run1")
    denied = telemetry.review_queue(workspace, ["example.com"])
    assert [d.name for d in denied] == ["evil.example.com"]


def test_review_queue_is_case_insensitive(workspace: Path) -> None:
    paths.ensure_project_state(workspace)
    (paths.current_run_dir(workspace) / "dns.log").write_text(DNS_LOG)
    telemetry.collect_dns(workspace, "run1")
    denied = telemetry.review_queue(workspace, ["API.ANTHROPIC.COM", "pastebin.com"])
    assert [d.name for d in denied] == ["telemetry.example.com"]


def test_run_records_store_a_prompt_digest_not_the_prompt(workspace: Path) -> None:
    paths.ensure_project_state(workspace)
    record = telemetry.RunRecord(
        id="abc",
        ts="2026-07-23T00:00:00Z",
        project="demo",
        profile="dev",
        prompt_sha=telemetry.prompt_digest("delete everything in prod"),
        duration_s=1.0,
        exit_code=0,
    )
    telemetry.record_run(workspace, record)
    body = (paths.project_state_dir(workspace) / telemetry.RUNS_INDEX).read_text()
    assert "delete everything" not in body
    assert record.prompt_sha in body


def test_runs_index_is_append_only(workspace: Path) -> None:
    paths.ensure_project_state(workspace)
    for i in range(3):
        telemetry.record_run(
            workspace,
            telemetry.RunRecord(
                id=str(i),
                ts="t",
                project="demo",
                profile="dev",
                prompt_sha="x",
                duration_s=0.0,
                exit_code=0,
            ),
        )
    assert [row["id"] for row in telemetry.runs(workspace)] == ["0", "1", "2"]


def test_session_id_and_tool_calls_from_transcript(tmp_path: Path) -> None:
    path = tmp_path / "t.jsonl"
    path.write_text(
        "\n".join(
            json.dumps(event)
            for event in [
                {"type": "system", "subtype": "init", "session_id": "sess-123"},
                {
                    "type": "assistant",
                    "message": {
                        "content": [
                            {"type": "text", "text": "hi"},
                            {"type": "tool_use", "name": "search"},
                        ]
                    },
                },
                {"type": "result", "subtype": "success"},
            ]
        )
    )
    assert telemetry.session_id_from_transcript(path) == "sess-123"
    assert telemetry.tool_calls_from_transcript(path) == ["search"]


def test_transcript_survives_a_truncated_line(tmp_path: Path) -> None:
    path = tmp_path / "t.jsonl"
    path.write_text('{"type":"system","session_id":"s"}\n{"type":"assist')
    assert telemetry.session_id_from_transcript(path) == "s"


def test_counters_history_is_bounded(workspace: Path) -> None:
    paths.ensure_project_state(workspace)
    for i in range(210):
        telemetry.record_counters(
            workspace, f"run{i:04d}", telemetry.FirewallCounters(dropped_packets=i)
        )
    assert len(telemetry.counters(workspace)["runs"]) == 200


def _stamp(workspace: Path, run_id: str, ts: str) -> None:
    """Give one recorded run a known timestamp — _now() has one-second
    resolution, and 260 records land in the same second."""
    path = paths.project_state_dir(workspace) / telemetry.FW_COUNTERS
    history = json.loads(path.read_text(encoding="utf-8"))
    assert run_id in history["runs"], f"{run_id} was evicted by the write that recorded it"
    history["runs"][run_id]["ts"] = ts
    path.write_text(json.dumps(history, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_counters_history_evicts_the_oldest_runs_not_a_random_slice(workspace: Path) -> None:
    """Run ids are random hex, so bounding the file by sorting the *keys* threw
    away an arbitrary slice of the newest runs — sometimes the one just
    written — and kept months-old ones in their place."""
    import hashlib

    paths.ensure_project_state(workspace)
    # The same shape new_run_id() produces: eight hex chars, no relation to time.
    ids = [hashlib.sha256(str(i).encode()).hexdigest()[:8] for i in range(260)]
    for i, run_id in enumerate(ids):
        telemetry.record_counters(
            workspace, run_id, telemetry.parse_iptables_counters(IPTABLES)
        )
        _stamp(workspace, run_id, f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}Z")
    kept = telemetry.counters(workspace)["runs"]
    assert set(kept) == set(ids[-200:])


def test_a_failed_counter_read_does_not_persist_as_zero_drops(workspace: Path) -> None:
    """This is what the runner builds when `docker exec … iptables -L` fails.
    Serialised without that fact it is indistinguishable from a run the firewall
    never had to refuse — a zero presented as evidence of a clean run."""
    paths.ensure_project_state(workspace)
    failed = telemetry.FirewallCounters(raw="Error: No such container: abox-demo-dev")
    assert not failed.read_ok
    telemetry.record_counters(workspace, "run1", failed)
    stored = telemetry.counters(workspace)["runs"]["run1"]
    assert stored["read_ok"] is False
    assert "No such container" in stored["error"]


def test_a_real_counter_read_is_recorded_as_read(workspace: Path) -> None:
    """The positive path through the same field: a counter that was genuinely
    read must not be indistinguishable from one that was not."""
    paths.ensure_project_state(workspace)
    telemetry.record_counters(workspace, "run1", telemetry.parse_iptables_counters(IPTABLES))
    stored = telemetry.counters(workspace)["runs"]["run1"]
    assert stored["read_ok"] is True
    assert stored["error"] == ""
    assert stored["dropped_packets"] == 7


def test_reset_current_run_clears_the_previous_run(workspace: Path) -> None:
    paths.ensure_project_state(workspace)
    stale = paths.current_run_dir(workspace) / "dns.log"
    stale.write_text("old")
    telemetry.reset_current_run(workspace)
    assert not stale.exists()


def test_the_gateway_is_never_in_the_review_queue(workspace: Path) -> None:
    """The firewall opens a hole for the gateway, so flagging it every run would
    be a standing false positive that trains the reader to ignore this list."""
    from abox.manifest import GlobalConfig, Manifest, ProfileConfig, effective_allowlist

    paths.ensure_project_state(workspace)
    (paths.current_run_dir(workspace) / "dns.log").write_text(
        "Jul 23 21:00:29 dnsmasq[1]: query[A] abox-gw-dev from 172.18.0.3\n"
        "Jul 23 21:00:30 dnsmasq[1]: query[A] pastebin.com from 172.18.0.3\n"
    )
    telemetry.collect_dns(workspace, "run1")
    manifest = Manifest(project="demo", profile="dev")
    config = GlobalConfig(profiles={"dev": ProfileConfig(port=8811)})
    denied = telemetry.review_queue(workspace, effective_allowlist(manifest, config))
    assert [d.name for d in denied] == ["pastebin.com"]


def test_ignored_domains_leave_the_review_queue(workspace: Path) -> None:
    """The queue is only useful while it means "undecided": a domain already
    ruled on must stop reappearing, or the operator stops reading the list."""
    paths.ensure_project_state(workspace)
    (paths.current_run_dir(workspace) / "dns.log").write_text(
        "Jul 23 21:00:29 dnsmasq[1]: query[A] telemetry.vendor.io from 172.18.0.3\n"
        "Jul 23 21:00:30 dnsmasq[1]: query[A] pastebin.com from 172.18.0.3\n"
    )
    telemetry.collect_dns(workspace, "run1")
    denied = telemetry.review_queue(workspace, [], ignored=["telemetry.vendor.io"])
    assert [d.name for d in denied] == ["pastebin.com"]


def test_a_failed_counter_read_is_not_recorded_as_zero_drops(workspace: Path) -> None:
    """A column of zeroes that reads as a clean record.

    `iptables -L` failing yields FirewallCounters with every count zero, which
    landed in runs.jsonl as dropped_packets: 0 — indistinguishable from a run
    the firewall never had to refuse. read_ok was persisted inside the counters
    file but never reached RunRecord, so the one view an operator actually reads
    still showed a bare 0.
    """
    failed = telemetry.FirewallCounters(raw="Cannot connect to the Docker daemon")
    assert not failed.read_ok

    telemetry.record_run(
        workspace,
        telemetry.RunRecord(
            id="r1", ts="2026-08-02T00:00:00Z", project="p", profile="dev",
            prompt_sha="x", duration_s=1.0, exit_code=0,
            dropped_packets=failed.dropped_packets,
            counters_read_ok=failed.read_ok,
        ),
    )
    row = telemetry.runs(workspace)[-1]
    assert row["dropped_packets"] == 0
    assert row["counters_read_ok"] is False, "the failed read is invisible in the history"


def test_a_real_zero_is_still_a_real_zero(workspace: Path) -> None:
    """The positive path: a firewall that genuinely refused nothing must not be
    reported as an unknown, or the marker becomes noise."""
    live = telemetry.parse_iptables_counters(
        "Chain OUTPUT (policy DROP 0 packets, 0 bytes)\n"
        " pkts bytes target prot opt in out source destination\n"
        "    0     0 DROP   all  --  *  *   0.0.0.0/0  0.0.0.0/0\n"
    )
    assert live.read_ok
    telemetry.record_run(
        workspace,
        telemetry.RunRecord(
            id="r2", ts="2026-08-02T00:00:01Z", project="p", profile="dev",
            prompt_sha="x", duration_s=1.0, exit_code=0,
            dropped_packets=live.dropped_packets, counters_read_ok=live.read_ok,
        ),
    )
    assert telemetry.runs(workspace)[-1]["counters_read_ok"] is True
