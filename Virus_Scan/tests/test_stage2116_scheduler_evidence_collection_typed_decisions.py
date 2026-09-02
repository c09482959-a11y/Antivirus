"""Stage2116 scheduler evidence collection typed-decision closure."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.evidence.record_collection import (
    collect_scheduler_evidence,
    collect_scheduler_evidence_decision,
    looks_like_evidence_record_decision,
    scheduler_evidence_mapping_items_decision,
    scheduler_evidence_nested_source_decision,
)

_ROOT = Path(__file__).resolve().parents[2]
_TARGET = _ROOT / "Virus_Scan/scheduler/evidence/record_collection.py"


class _HostileEvidenceObject:
    def __getattribute__(self, name: str) -> object:
        raise AssertionError(f"caller hook invoked: {name}")


def _return_literals_for_target_functions() -> tuple[str, ...]:
    tree = ast.parse(_TARGET.read_text(encoding="utf-8"), filename=str(_TARGET))
    target_names = {
        "collect_scheduler_evidence",
        "looks_like_evidence_record",
        "_scheduler_evidence_sequence_items",
        "_collect_scheduler_evidence_source",
        "scheduler_evidence_mapping_items",
        "scheduler_evidence_nested_source",
    }
    literals: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name not in target_names:
            continue
        for child in ast.walk(node):
            if isinstance(child, ast.Return):
                literals.append(ast.unparse(child.value) if child.value is not None else "None")
    return tuple(literals)


def test_stage2116_record_collection_public_wrappers_no_longer_return_hidden_literals() -> None:
    returns = _return_literals_for_target_functions()

    assert "()" not in returns
    assert "None" not in returns
    assert "False" not in returns


def test_stage2116_record_collection_decisions_distinguish_missing_mapping_and_nested_source() -> None:
    mapping_decision = scheduler_evidence_mapping_items_decision(_HostileEvidenceObject())
    assert mapping_decision.items is None
    assert mapping_decision.reason == "unsupported_mapping_source"

    shape_decision = looks_like_evidence_record_decision({"not_stage": "scheduler"})
    assert shape_decision.looks_like is False
    assert shape_decision.reason == "missing_stage_key"

    nested_decision = scheduler_evidence_nested_source_decision((("stage", "scheduler"),))
    assert nested_decision.found is False
    assert nested_decision.reason == "missing_nested_evidence_source"


def test_stage2116_record_collection_preserves_public_output_while_exposing_replayable_reason() -> None:
    missing = collect_scheduler_evidence_decision(None)
    assert missing.records == ()
    assert missing.reason == "missing_source"
    assert collect_scheduler_evidence(None) == ()

    rejected = collect_scheduler_evidence_decision(_HostileEvidenceObject())
    assert rejected.reason == "unsupported_mapping_source"
    assert len(rejected.records) == 1
    assert rejected.records[0].error_category == "scheduler_evidence_source_rejected"

    record = SchedulerEvidenceRecord(stage="scheduler", state="failed", error_category="unit")
    preserved = collect_scheduler_evidence_decision({"scheduler_evidence": (record,)})
    assert preserved.records == (record,)
    assert preserved.reason == "nested_sequence:record_source"
