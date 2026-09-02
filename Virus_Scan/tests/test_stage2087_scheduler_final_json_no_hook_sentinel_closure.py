"""Stage2087 scheduler final-JSON sentinel and no-hook boundary guards."""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Final

from Virus_Scan.scheduler.evidence.final_json_checkpoint_projection import (
    failure_record_from_checkpoint_status,
)
from Virus_Scan.scheduler.evidence.final_json_exact_fields import (
    exact_contains_fragment,
    exact_flag_value,
    exact_mapping_items,
    exact_text,
)
from Virus_Scan.scheduler.evidence.final_json_failure_projection import (
    failure_record_from_scheduler_result,
)
from Virus_Scan.scheduler.evidence.final_json_replay_projection import (
    failure_record_from_replay_status,
)
from Virus_Scan.scheduler.evidence.final_json_scheduler_status_projection import (
    failure_record_from_existing_scheduler_section,
)
from Virus_Scan.scheduler.evidence.record_collection import (
    collect_scheduler_evidence,
    scheduler_evidence_mapping_items,
)

_ROOT: Final = Path(__file__).resolve().parents[2]

_STAGE2087_SENTINEL_ROWS: Final = (
    ("Virus_Scan/scheduler/evidence/final_json_exact_fields.py", 25, "exact_mapping_items", "return None"),
    ("Virus_Scan/scheduler/evidence/final_json_exact_fields.py", 54, "exact_text", "return \"\""),
    ("Virus_Scan/scheduler/evidence/final_json_exact_fields.py", 61, "exact_text", "return None"),
    ("Virus_Scan/scheduler/evidence/final_json_exact_fields.py", 74, "exact_flag_value", "return False"),
    ("Virus_Scan/scheduler/evidence/final_json_exact_fields.py", 126, "exact_contains_fragment", "return False"),
    ("Virus_Scan/scheduler/evidence/final_json_exact_fields.py", 139, "exact_contains_fragment", "return False"),
    ("Virus_Scan/scheduler/evidence/final_json_exact_fields.py", 151, "_exact_evidence_source", "return ()"),
    ("Virus_Scan/scheduler/evidence/final_json_exact_fields.py", 160, "_exact_evidence_source", "return None"),
    ("Virus_Scan/scheduler/evidence/final_json_checkpoint_projection.py", 26, "failure_record_from_checkpoint_status", "return None"),
    ("Virus_Scan/scheduler/evidence/final_json_checkpoint_projection.py", 36, "failure_record_from_checkpoint_status", "return None"),
    ("Virus_Scan/scheduler/evidence/final_json_failure_projection.py", 34, "failure_record_from_scheduler_result", "return None"),
    ("Virus_Scan/scheduler/evidence/final_json_failure_projection.py", 89, "_scheduler_result_keys", "return ()"),
    ("Virus_Scan/scheduler/evidence/final_json_replay_projection.py", 20, "failure_record_from_replay_status", "return None"),
    ("Virus_Scan/scheduler/evidence/final_json_replay_projection.py", 25, "failure_record_from_replay_status", "return None"),
    ("Virus_Scan/scheduler/evidence/final_json_scheduler_status_projection.py", 24, "failure_record_from_existing_scheduler_section", "return None"),
    ("Virus_Scan/scheduler/evidence/final_json_scheduler_status_projection.py", 29, "failure_record_from_existing_scheduler_section", "return None"),
    ("Virus_Scan/scheduler/evidence/final_json_scheduler_status_projection.py", 31, "failure_record_from_existing_scheduler_section", "return None"),
)


class _HostileObject:
    def __getattribute__(self, name: str) -> object:
        raise AssertionError(f"caller hook invoked: {name}")


def _enclosing_function(tree: ast.AST, line: int) -> ast.FunctionDef | ast.AsyncFunctionDef:
    functions = tuple(
        node
        for node in ast.walk(tree)
        if type(node) in {ast.FunctionDef, ast.AsyncFunctionDef}
        and node.lineno <= line <= node.end_lineno
    )
    assert functions
    return max(functions, key=lambda node: node.lineno)


def test_stage2087_closed_scheduler_final_json_rows_still_match_current_source() -> None:
    for relative_path, line, symbol, expected_source in _STAGE2087_SENTINEL_ROWS:
        path = _ROOT / relative_path
        source = path.read_text(encoding="utf-8")
        assert source.splitlines()[line - 1].strip() == expected_source
        function = _enclosing_function(ast.parse(source, filename=str(path)), line)
        assert function.name == symbol


def test_stage2087_exact_field_sentinels_reject_hostile_objects_without_hooks() -> None:
    hostile = _HostileObject()
    assert exact_mapping_items(hostile) is None
    assert exact_text(hostile) is None
    assert exact_flag_value(hostile, default=True) is True
    assert exact_contains_fragment(hostile, "missing") is False
    assert scheduler_evidence_mapping_items(hostile) is None

    rejected = collect_scheduler_evidence(hostile)
    assert len(rejected) == 1
    assert rejected[0].state == "failed"
    assert rejected[0].error_category == "scheduler_evidence_source_rejected"
    assert rejected[0].fatal is True


def test_stage2087_projection_none_returns_are_clean_absence_not_hidden_failure() -> None:
    assert failure_record_from_checkpoint_status({}, {}) is None
    assert failure_record_from_checkpoint_status({}, {"status": "ok"}) is None
    checkpoint_failure = failure_record_from_checkpoint_status(
        {"job_id": "job-1"},
        {"status": "failed", "error_category": "checkpoint_write_failed"},
    )
    assert checkpoint_failure is not None
    assert checkpoint_failure.state == "failure"
    assert checkpoint_failure.error_category == "checkpoint_write_failed"

    assert failure_record_from_scheduler_result({"scan_integrity": {}}) is None
    worker_failure = failure_record_from_scheduler_result(
        {"worker_output_publication_failed": True, "job_id": "job-2"}
    )
    assert worker_failure is not None
    assert worker_failure.state == "failure"
    assert worker_failure.final_json_must_record is True

    assert failure_record_from_replay_status({}, {}) is None
    assert failure_record_from_replay_status({}, {"matched": True, "mismatches": ()}) is None
    replay_failure = failure_record_from_replay_status(
        {"job_id": "job-3"},
        {"matched": False, "mismatches": ("field",)},
    )
    assert replay_failure is not None
    assert replay_failure.error_category == "replay_mismatch"
    assert replay_failure.replay_must_record is True

    assert failure_record_from_existing_scheduler_section({}, {}) is None
    assert failure_record_from_existing_scheduler_section({}, {"status": "ok"}) is None
    degraded_section = failure_record_from_existing_scheduler_section(
        {"job_id": "job-4"},
        {"status": "degraded", "reason": "retry timeout"},
    )
    assert degraded_section is not None
    assert degraded_section.state == "degraded"
    assert degraded_section.retry_state_affected is True
    assert degraded_section.timeout_state_affected is True
