from Virus_Scan.runtime.determinism import deterministic_queue_order, stable_evidence_order, make_governance_snapshot
from Virus_Scan.runtime.telemetry_governance import TelemetryBudget
from Virus_Scan.models.replay_introspection import ReplayNode, validate_replay_lineage


def test_deterministic_queue_order_and_snapshot_digest_are_stable():
    paths = ["b/file.rpy", "A/file.js", "a/File.js"]
    assert deterministic_queue_order(paths)[0] == "A/file.js"
    snap1 = make_governance_snapshot(queue_state={"b": 2, "a": 1})
    snap2 = make_governance_snapshot(queue_state={"a": 1, "b": 2})
    assert snap1.stable_digest() == snap2.stable_digest()
    ev = stable_evidence_order([{"tag":"z","source":"b"}, {"tag":"a","source":"z"}])
    assert ev[0]["tag"] == "a"


def test_telemetry_budget_suppresses_repetitive_noncritical_bursts():
    b = TelemetryBudget(max_events_per_key=2, burst_window_sec=999)
    assert b.record("parse_fail") is not None
    assert b.record("parse_fail") is not None
    assert b.record("parse_fail") is None
    assert b.record("parse_fail", severity="critical") is not None


def test_replay_lineage_integrity_detects_depth_limit():
    nodes = [ReplayNode("a"), ReplayNode("b", "a"), ReplayNode("c", "b")]
    assert validate_replay_lineage(nodes, max_depth=4)["ok"]
    assert not validate_replay_lineage(nodes, max_depth=2)["ok"]
