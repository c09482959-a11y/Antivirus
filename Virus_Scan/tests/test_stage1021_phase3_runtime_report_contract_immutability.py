from __future__ import annotations

import pytest

from Virus_Scan.runtime.causal_snapshots import CausalReplaySnapshot
from Virus_Scan.runtime.determinism import GovernanceSnapshot
from Virus_Scan.runtime.emergent_simulation import EmergentSimulationReport, EmergentScenarioResult
from Virus_Scan.runtime.governance_recovery import GovernanceConvergenceReport
from Virus_Scan.runtime.immutable_core import RuntimeTransition
from Virus_Scan.runtime.stability_policy import StabilizationDecision
from Virus_Scan.runtime.stabilization_arbitration import ArbitrationResult
from Virus_Scan.runtime.topology_stabilization import TopologyStabilizationReport
from Virus_Scan.runtime.transactional_state import RuntimeCheckpoint


def test_stage1021_runtime_transition_freezes_value_payload() -> None:
    value = {"nested": {"items": ["a"]}}
    transition = RuntimeTransition("runtime", "set", "key", value)
    value["nested"]["items"].append("b")

    assert transition.canonical()["value"] == {"nested": {"items": ["a"]}}
    with pytest.raises(TypeError):
        transition.value["nested"]["items"] += ("c",)  # type: ignore[index,operator]


def test_stage1021_runtime_checkpoint_and_governance_snapshot_freeze_nested_state() -> None:
    values = {"queue": {"items": ["one"]}}
    checkpoint = RuntimeCheckpoint("runtime", 1, "digest", values=values)
    governance = GovernanceSnapshot(queue_state=values, scheduler_decisions=[{"decision": ["go"]}])
    values["queue"]["items"].append("two")

    assert checkpoint.canonical()["values"] == {"queue": {"items": ["one"]}}
    assert governance.as_stable_payload()["queue_state"] == {"queue": {"items": ["one"]}}
    assert governance.as_stable_payload()["scheduler_decisions"] == [{"decision": ["go"]}]
    with pytest.raises(TypeError):
        checkpoint.values["queue"]["items"] += ("blocked",)  # type: ignore[index,operator]


def test_stage1021_causal_replay_snapshot_freezes_direct_construction_payloads() -> None:
    events = ({"seq": 1, "payload": {"tags": ["x"]}},)
    budgets = {"global": {"costs": [1]}}
    snap = CausalReplaySnapshot(1, 1, 1, "digest", events=events, budgets=budgets)
    budgets["global"]["costs"].append(2)
    events[0]["payload"]["tags"].append("y")

    assert snap.as_dict()["events"][0]["payload"]["tags"] == ["x"]
    assert snap.as_dict()["budgets"]["global"]["costs"] == [1]


def test_stage1021_runtime_governance_reports_freeze_nested_metrics_and_details() -> None:
    metrics = {"hot": {"ids": ["w1"]}}
    details = {"topology": {"actions": ["freeze"]}}

    topology = TopologyStabilizationReport(True, 0.1, metrics=metrics)
    convergence = GovernanceConvergenceReport(True, metrics=metrics)
    stabilization = StabilizationDecision("degrade", "reason", details=details)
    arbitration = ArbitrationResult("degrade", "reason", details=details)
    emergent = EmergentSimulationReport(
        False,
        0.5,
        scenarios=(EmergentScenarioResult("cascade", 0.7, True),),
        graceful_degradation=details,
        immutable_invariants=metrics,
    )

    metrics["hot"]["ids"].append("w2")
    details["topology"]["actions"].append("mutated")

    assert topology.as_dict()["metrics"]["hot"]["ids"] == ["w1"]
    assert convergence.as_dict()["metrics"]["hot"]["ids"] == ["w1"]
    assert stabilization.as_dict()["details"]["topology"]["actions"] == ["freeze"]
    assert arbitration.as_dict()["details"]["topology"]["actions"] == ["freeze"]
    assert emergent.as_dict()["graceful_degradation"]["topology"]["actions"] == ["freeze"]
    assert emergent.as_dict()["immutable_invariants"]["hot"]["ids"] == ["w1"]

from Virus_Scan.runtime.architecture_governance import SemanticOwnershipReport
from Virus_Scan.runtime.readonly import ReadonlyRuntimeView


def test_stage1021_readonly_runtime_view_direct_construction_freezes_state() -> None:
    source = {"runtime": {"paths": ["a"]}}
    view = ReadonlyRuntimeView(source)
    source["runtime"]["paths"].append("b")

    assert view.state["runtime"]["paths"] == ("a",)
    assert view.as_dict()["runtime"]["paths"] == ["a"]


def test_stage1021_semantic_ownership_report_freezes_ownership_mapping() -> None:
    ownership = {"scanner": "observe"}
    report = SemanticOwnershipReport(True, ownership=ownership)
    ownership["scanner"] = "mutated"

    assert report.ownership["scanner"] == "observe"
    assert report.as_dict()["ownership"] == {"scanner": "observe"}
