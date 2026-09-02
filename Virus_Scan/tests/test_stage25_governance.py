from Virus_Scan.runtime.determinism import canonicalize_result_mapping, snapshot_runtime_state
from Virus_Scan.models.replay_introspection import ReplayNode, validate_replay_lineage, why_suspicious_report, garbage_collect_replay
from Virus_Scan.runtime.telemetry_governance import WorkloadTelemetryBudget
from Virus_Scan.detection.evidence.normalization import correlation_ceiling, confidence_decay
from Virus_Scan.runtime.governance_invariants import evaluate_runtime_invariants, assert_acyclic_edges
from Virus_Scan.scheduler.queue.admission import build_workload_classification_plan
from Virus_Scan.scheduler.queue.admission_fairness import weighted_fair_interleave


def test_deterministic_canonical_result_order_and_snapshot_digest():
    a = canonicalize_result_mapping({"b": {"tags": ["z", "a"]}, "A": {"x": 1}})
    b = canonicalize_result_mapping({"A": {"x": 1}, "b": {"tags": ["a", "z"]}})
    assert list(a) == ["A", "b"]
    assert a == b
    assert snapshot_runtime_state(queue_state={"b": 2, "a": 1}).stable_digest() == snapshot_runtime_state(queue_state={"a": 1, "b": 2}).stable_digest()


def test_replay_budget_introspection_and_cycle_detection():
    nodes = [ReplayNode("root", tags=["loader"], influence=0.2), ReplayNode("child", "root", ["network"], 0.8, "heuristic", "test")]
    rep = validate_replay_lineage(nodes, max_depth=4, max_fanout=4, max_nodes=4)
    assert rep["ok"]
    why = why_suspicious_report(nodes, node_id="child")
    assert why["inheritance_chain"][0]["node"] == "child"
    assert not validate_replay_lineage([ReplayNode("a", "b"), ReplayNode("b", "a")])["ok"]
    assert garbage_collect_replay([ReplayNode(str(i), influence=0.0) for i in range(20)])


def test_telemetry_budget_suppresses_bursts_but_keeps_summary():
    t = WorkloadTelemetryBudget(max_events_per_key=2, max_events_total=10, workload_id="w")
    emitted = [t.record_governance("parse_error", payload={"x": i}) for i in range(6)]
    assert sum(1 for x in emitted if x) == 2
    assert t.summary()["suppressed_total"] >= 4


def test_correlation_ceiling_and_decay():
    weak = correlation_ceiling(["base64", "encoded_payload"], base_score=90)
    assert weak["capped"] and weak["score"] < 60
    strong = correlation_ceiling(["unity_native_injection_chain", "memory_allocate", "thread_execution"], base_score=90)
    assert strong["score"] >= 78
    assert confidence_decay(1.0, lineage_distance=3, replay_depth=3) < 1.0


def test_governance_invariants_and_weighted_fair_interleave():
    assert assert_acyclic_edges([("a", "b"), ("b", "c")]) == []
    assert assert_acyclic_edges([("a", "b"), ("b", "a")])
    rep = evaluate_runtime_invariants(replay_depth=99, telemetry_events=9999)
    assert not rep.ok
    ordered = weighted_fair_interleave(
        build_workload_classification_plan(["z.zip", "a.txt", "b.dll", "c.png"]).targets
    )
    assert ordered[0].path.endswith((".png", ".txt"))
