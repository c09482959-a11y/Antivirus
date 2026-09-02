from __future__ import annotations

import ast
import json
from pathlib import Path

from Virus_Scan.scheduler.evidence.final_json_projection import build_final_json_scheduler_section
from Virus_Scan.scheduler.evidence.records import build_scheduler_json_evidence_section
from Virus_Scan.scheduler.evidence.final_json_contract_support import mapping_from_scheduler_value


_SUPPORT_PATH = Path(__file__).resolve().parents[2] / "Virus_Scan/scheduler/evidence/final_json_contract_support.py"


class HostileSchedulerStatus:
    touched = 0

    def as_dict(self):  # pragma: no cover - failure proves unsafe hook returned
        type(self).touched += 1
        raise AssertionError("scheduler as_dict touched")

    def __iter__(self):  # pragma: no cover - failure proves unsafe hook returned
        type(self).touched += 1
        raise AssertionError("scheduler iter touched")

    def __str__(self):  # pragma: no cover - failure proves unsafe hook returned
        type(self).touched += 1
        raise AssertionError("scheduler str touched")

    def __repr__(self):  # pragma: no cover - failure proves unsafe hook returned
        type(self).touched += 1
        raise AssertionError("scheduler repr touched")


def test_stage1580_empty_scheduler_status_values_emit_explicit_evidence() -> None:
    for value, reason in (
        (None, "scheduler_status_missing"),
        ("", "scheduler_status_blank_text"),
        ({}, "scheduler_status_empty_container"),
        ([], "scheduler_status_empty_container"),
        ((), "scheduler_status_empty_container"),
    ):
        status = mapping_from_scheduler_value(value)
        assert status["status"] == "failed"
        assert status["failed"] is True
        assert status["empty_scheduler_status"] is True
        assert status["error_category"] == "scheduler_status_empty"
        assert status["reason"] == reason
        assert status["final_json_must_record"] is True
        assert status["checkpoint_must_record"] is True
        assert status["replay_must_record"] is True
        assert json.dumps(status, sort_keys=True)


def test_stage1580_unsupported_scheduler_status_does_not_call_hooks() -> None:
    HostileSchedulerStatus.touched = 0

    status = mapping_from_scheduler_value(HostileSchedulerStatus())

    assert status["unsupported_scheduler_value"] is True
    assert status["error_category"] == "scheduler_json_materialization_unsupported"
    assert HostileSchedulerStatus.touched == 0


def test_stage1580_empty_checkpoint_replay_placeholders_stay_neutral() -> None:
    section = build_scheduler_json_evidence_section(())
    projected = build_final_json_scheduler_section({"scheduler": section})

    assert projected is not None
    assert projected["scheduler_status"] == "ok"
    assert projected["evidence"] == []
    assert projected["checkpoint"] == {}
    assert projected["replay_comparison_result"] == {}


def test_stage1580_scheduler_status_support_has_no_empty_mapping_failure_return() -> None:
    tree = ast.parse(_SUPPORT_PATH.read_text(encoding="utf-8"), filename=str(_SUPPORT_PATH))
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict) and len(node.value.keys) == 0:
            offenders.append(f"{_SUPPORT_PATH.name}:{node.lineno}:return {{}}")

    assert offenders == []
