from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.runtime.fact_event_store import FactEventStore
from Virus_Scan.runtime.governance_planes import (
    GovernancePlane,
    governance_planes_snapshot,
    make_governance_planes,
    observe_governance_plane,
)
from Virus_Scan.runtime.governance_recovery import plan_adaptive_rollback, verify_governance_convergence
from Virus_Scan.runtime import governance_read_model as read_model
from Virus_Scan.runtime.stability_policy import decide_stabilization
from Virus_Scan.runtime.topology_stabilization import analyze_topology_pressure


@dataclass(frozen=True)
class _Event:
    seq: int
    domain: str = "runtime"
    kind: str = "event"
    event_key: str = "key"
    parent_seq: int | None = None
    causal_depth: int = 0
    suppressed_count: int = 0


def test_fact_event_store_prunes_old_events_and_snapshots_are_deterministic():
    store = FactEventStore(max_events=2)
    first = _Event(2, domain="scheduler", kind="claim", event_key="b")
    second = _Event(1, domain="runtime", kind="init", event_key="a", parent_seq=2, causal_depth=1)
    third = _Event(3, domain="scanner", kind="evidence", event_key="c", parent_seq=1, causal_depth=2)

    assert store.append(first, parent_seq=None, depth=0) == []
    assert store.append(second, parent_seq=2, depth=1) == []
    pruned = store.append(third, parent_seq=1, depth=2)

    assert pruned == [first]
    assert tuple(store.by_seq) == (1, 3)
    assert 2 not in store.parent
    assert 2 not in store.depth
    assert store.children.get(1) == 1
    assert [event.seq for event in store.snapshot()] == [1, 3]
    assert isinstance(store.snapshot(), tuple)


def test_governance_planes_trip_release_and_snapshot_dynamic_planes():
    plane = GovernancePlane("telemetry", trip_threshold=10.0, release_threshold=3.0, cooldown_sec=0.0)

    tripped = plane.observe(12.0)
    assert tripped["state"] == "tripped"
    assert tripped["transitioned"] is True
    assert tripped["transitions"] == 1

    released = plane.decay()
    for _ in range(11):
        released = plane.decay()
    assert released["state"] == "normal"
    assert plane.transitions == 2

    planes = make_governance_planes()
    dynamic = observe_governance_plane(planes, "custom", 4.0)
    assert dynamic["plane"] == "custom"
    assert "custom" in planes

    snapshot = governance_planes_snapshot(planes)
    assert list(snapshot) == sorted(snapshot)
    assert snapshot["custom"]["pressure"] == 4.0
    assert set(snapshot["custom"]) == {"state", "pressure", "transitions"}


def test_topology_stabilization_reports_bounded_anomalies_and_actions():
    events = tuple(
        _Event(
            seq=i,
            domain="scheduler",
            kind="retry",
            event_key=f"retry:{i}",
            parent_seq=1 if i > 1 else None,
            causal_depth=3,
            suppressed_count=300,
        )
        for i in range(1, 7)
    )

    report = analyze_topology_pressure(events, fanout_limit=2, depth_limit=1, burst_limit=3)
    data = report.as_dict()

    assert data["ok"] is False
    assert data["pressure"] == 1.0
    assert any(item.startswith("fanout:") for item in data["anomalies"])
    assert any(item.startswith("depth:") for item in data["anomalies"])
    assert any(item.startswith("burst:scheduler:retry") for item in data["anomalies"])
    assert any(item.startswith("suppression:") for item in data["anomalies"])
    assert data["actions"] == sorted(data["actions"])
    assert data["metrics"]["event_count"] == len(events)
    assert data["metrics"]["max_depth"] == 3


def test_stability_policy_degrades_from_invariants_topology_and_replay_pressure():
    decision = decide_stabilization(
        invariant_snapshot={"ok": False},
        budgets={"worker-a": {"suppressed": 200, "cost": 5000.0}},
        topology={"event_count": 100, "pressure": 0.7, "causal_forecast": {"action": "isolate_topology_region", "anomaly_probability": 0.6}},
        lineage_pressure={"action": "compress_lineage", "pressure": 0.8},
    )
    data = decision.as_dict()

    assert data["action"] == "degrade"
    assert "runtime_invariant_violation" in data["reason"]
    assert "event_stream_pressure" in data["reason"]
    assert data["freeze_replay"] is True
    assert data["suppress_telemetry"] is True
    assert data["isolate_workload"] is True
    assert data["reduce_concurrency"] is True
    assert data["compress_lineage"] is True
    assert data["details"]["hot_workloads"] == ["worker-a"]


def test_governance_recovery_detects_inconsistent_snapshots_and_plans_rollback():
    snapshot = {
        "event_budgets": {"worker-a": {"suppressed": 0, "cost": 0.0}},
        "governance_planes": {"telemetry": {"state": "normal", "pressure": 0.0, "transitions": 0}},
        "stabilization_policy": {
            "action": "normal",
            "freeze_replay": True,
            "suppress_telemetry": True,
            "reduce_concurrency": True,
            "reason": "unit_policy",
        },
        "replay_lineage_pressure": {"action": "normal", "pressure": 0.0},
        "topology_pressure_forecast": {"action": "normal", "pressure": 0.0},
        "event_invariants": {"ok": True},
    }

    convergence = verify_governance_convergence(snapshot)
    assert convergence.ok is False
    assert "replay" in convergence.drift_domains
    assert "telemetry" in convergence.drift_domains
    assert "scheduler" in convergence.drift_domains
    assert "policy_replay_freeze_without_replay_pressure" in convergence.reasons

    rollback = plan_adaptive_rollback(snapshot, {"sequence": 42})
    rollback_data = rollback.as_dict()
    assert rollback_data["required"] is True
    assert rollback_data["checkpoint_sequence"] == 42
    assert "restore_event_checkpoint" in rollback_data["actions"]
    assert "keep_replay_frozen_until_convergence" in rollback_data["actions"]


def test_stage1968_governance_snapshots_filter_hostile_keys_without_hooks():
    class _HostileKey:
        touched = 0

        def __str__(self):  # pragma: no cover - regression asserts no access
            type(self).touched += 1
            raise AssertionError("do not stringify caller key")

        def __lt__(self, other):  # pragma: no cover - regression asserts no access
            type(self).touched += 1
            raise AssertionError("do not compare caller key")

    class _HostilePlane:
        pass

    planes = {"safe": GovernancePlane("safe"), _HostileKey(): _HostilePlane()}
    snapshot = governance_planes_snapshot(planes)

    assert tuple(snapshot) == ("safe",)
    assert _HostileKey.touched == 0

    semantic_budget = {("source", "target", "kind"): 1.5, (_HostileKey(), "target", "kind"): 9.0}
    budget_snapshot = read_model._semantic_budget_snapshot(semantic_budget)

    assert budget_snapshot == {"source|target|kind": 1.5}
    assert _HostileKey.touched == 0

    mapping_snapshot = read_model._exact_mapping_snapshot({"pressure": 0.5, _HostileKey(): 1.0})

    assert mapping_snapshot == {"pressure": 0.5}
    assert _HostileKey.touched == 0
