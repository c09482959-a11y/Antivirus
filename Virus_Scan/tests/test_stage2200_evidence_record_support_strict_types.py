"""Stage2200 scheduler evidence-record support strict typing guards."""
from __future__ import annotations

import ast
from pathlib import Path
from types import MappingProxyType

import pytest

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.contracts.evidence_record_support import (
    first_scheduler_mapping_value,
    merge_field_issue,
    scheduler_bool_field,
    scheduler_context_with_issues,
    scheduler_mapping_items,
    scheduler_mapping_value,
    scheduler_text_field,
)

_ROOT = Path(__file__).resolve().parents[2]
_TARGET = _ROOT / "Virus_Scan" / "scheduler" / "contracts" / "evidence_record_support.py"


class HostileValue:
    def __getattribute__(self, name: str):  # pragma: no cover - must not be invoked
        raise AssertionError(f"hostile __getattribute__ invoked for {name}")

    def __iter__(self):  # pragma: no cover - must not be invoked
        raise AssertionError("hostile __iter__ invoked")

    def __bool__(self):  # pragma: no cover - must not be invoked
        raise AssertionError("hostile __bool__ invoked")

    def __str__(self):  # pragma: no cover - must not be invoked
        raise AssertionError("hostile __str__ invoked")


class HostileIssues(HostileValue):
    pass


def test_stage2200_evidence_record_support_has_no_any_annotations() -> None:
    source = _TARGET.read_text(encoding="utf-8")
    tree = ast.parse(source)
    assert "Any" not in source
    assert not [node.lineno for node in ast.walk(tree) if isinstance(node, ast.Name) and node.id == "Any"]


def test_stage2200_mapping_helpers_preserve_no_hook_unavailable_evidence() -> None:
    hostile = HostileValue()
    assert scheduler_mapping_items(hostile) is None
    assert scheduler_mapping_value(hostile, "missing", default="fallback") == "fallback"
    assert first_scheduler_mapping_value(hostile, "a", "b", default="fallback") == "fallback"

    proxy = MappingProxyType({"a": "kept", "b": 2})
    assert scheduler_mapping_items(proxy) == (("a", "kept"), ("b", 2))
    assert scheduler_mapping_value(proxy, "a") == "kept"
    assert first_scheduler_mapping_value(proxy, "missing", "b") == 2


def test_stage2200_field_helpers_emit_typed_issues_without_hooks() -> None:
    hostile = HostileValue()
    text, text_issue = scheduler_text_field(hostile, field_name="stage", default_text="scheduler")
    assert text == "scheduler"
    assert text_issue is not None
    assert text_issue[0] == "stage_materialization"
    assert text_issue[1]["scheduler_evidence_field_rejected"] is True

    flag, bool_issue = scheduler_bool_field(hostile, field_name="fatal", default=False)
    assert flag is False
    assert bool_issue is not None
    assert bool_issue[0] == "fatal_materialization"
    assert bool_issue[1]["reason"] == "scheduler_evidence_bool_rejected"


def test_stage2200_context_merge_and_record_from_mapping_remain_replayable() -> None:
    hostile = HostileValue()
    merged = scheduler_context_with_issues({"existing": True}, {"issue": {"reason": "kept"}})
    assert dict(merged) == {"existing": True, "issue": {"reason": "kept"}}

    rejected = scheduler_context_with_issues({"existing": True}, HostileIssues())
    assert rejected["existing"] is True
    assert rejected["context_issues_materialization"]["unsupported_scheduler_value"] is True

    out: dict[str, object] = {}
    assert merge_field_issue(out, None) is None
    assert out == {}
    assert merge_field_issue(out, ("stage_materialization", {"reason": "kept"})) is None
    assert out == {"stage_materialization": {"reason": "kept"}}

    record = SchedulerEvidenceRecord.from_mapping({"stage": hostile, "fatal": hostile, "context": hostile})
    assert record.stage == "scheduler"
    assert record.fatal is False
    data = record.as_dict()
    assert data["context"]["context_materialization"]["unsupported_scheduler_value"] is True
