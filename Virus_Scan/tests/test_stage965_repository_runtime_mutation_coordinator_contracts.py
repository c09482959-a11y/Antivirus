import ast
from pathlib import Path

import pytest

from Virus_Scan.runtime.mutation_coordinator import RuntimeRoot


def test_stage965_runtime_root_rejects_undeclared_domains_and_foreign_owned_keys_without_creating_state():
    root = RuntimeRoot()

    before = set(root.snapshot().keys())
    with pytest.raises(RuntimeError, match="undeclared runtime mutation domain"):
        root.domain("private_scheduler_shadow")
    assert set(root.snapshot().keys()) == before

    scheduler = root.domain("scheduler")
    with pytest.raises(RuntimeError, match="does not own key"):
        scheduler.set("root.cross_domain_runtime_key", "leak", kind="debt")

    assert scheduler.snapshot() == {}
    assert scheduler.generation == 0
    assert scheduler.mutation_count == 0
    assert scheduler.mutation_lineage() == ()


def test_stage965_semantic_influence_budget_caps_weight_and_publishes_throttle_evidence():
    root = RuntimeRoot()

    first = dict(root.record_influence("scanner", "reporting", "evidence", weight=10.0, lineage_id="stage965-semantic"))
    second = dict(root.record_influence("scanner", "reporting", "evidence", weight=10.0, lineage_id="stage965-semantic"))
    third = dict(root.record_influence("scanner", "reporting", "evidence", weight=10.0, lineage_id="stage965-semantic"))

    assert first["weight"] == 10.0
    assert first["applied"] == 10.0
    assert first["throttled"] is False

    assert second["weight"] == 12.0
    assert second["applied"] == 2.0
    assert second["throttled"] is True

    assert third["weight"] == 12.0
    assert third["applied"] == 0.0
    assert third["throttled"] is True

    semantic_events = root.domain("semantic").event_snapshot()
    kinds = [event.kind for event in semantic_events]
    assert "influence_budget" in kinds
    assert "influence_throttled" in kinds
    assert any(event.payload["source"] == "scanner" and event.payload["target"] == "reporting" for event in semantic_events)

    governance = root.governance_snapshot()
    assert governance["semantic_budget"] == {"scanner|reporting|evidence": 12.0}
    assert governance["circuit_breakers"]["semantic:scanner|reporting|evidence"] >= 2


def test_stage965_runtime_pressure_records_governance_evidence_and_circuit_breaker_without_mutating_scanner_domain():
    root = RuntimeRoot()

    payload = dict(root.record_pressure("scanner", amount=30.0, workload_id="stage965-workload", lineage_id="stage965-pressure"))

    assert payload["domain"] == "scanner"
    assert payload["pressure"] == 30.0
    assert payload["tripped"] is True
    assert payload["governance_decision"] == "recommend_isolation"
    assert payload["plane"]["plane"] == "saturation"

    governance_events = root.domain("governance").event_snapshot()
    assert [event.kind for event in governance_events][-2:] == ["pressure", "circuit_breaker"]
    assert governance_events[-1].payload["domain"] == "scanner"
    assert root.domain("scanner").snapshot() == {}

    snapshot = root.governance_snapshot()
    assert snapshot["pressure"]["scanner"] == 30.0
    assert snapshot["circuit_breakers"]["scanner"] == 1


def test_stage965_mutation_commit_is_atomic_when_event_contract_publication_fails():
    root = RuntimeRoot()
    scheduler = root.domain("scheduler")

    with pytest.raises(KeyError, match="unregistered event contract: scheduler:set"):
        scheduler.set("queue.claim", "claimed-by-worker")

    assert scheduler.snapshot() == {}
    assert scheduler.generation == 0
    assert scheduler.mutation_count == 0
    assert scheduler.mutation_lineage() == ()
    assert scheduler.event_snapshot() == ()


def test_stage965_mutation_coordinator_keeps_static_import_boundary():
    source_path = Path("Virus_Scan/runtime/mutation_coordinator.py")
    tree = ast.parse(source_path.read_text(encoding="utf-8"))

    function_scope_imports = []
    dynamic_imports = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for child in ast.walk(node):
                if isinstance(child, (ast.Import, ast.ImportFrom)):
                    function_scope_imports.append((node.name, child.lineno))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "__import__":
            dynamic_imports.append(node.lineno)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "importlib":
                dynamic_imports.append(node.lineno)

    assert function_scope_imports == []
    assert dynamic_imports == []
