import ast
from pathlib import Path
from unittest.mock import patch

from Virus_Scan.scheduler.queue import admission_guard, authority
from Virus_Scan.scheduler.queue.admission_guard import process_queue_enqueue_guard
from Virus_Scan.scheduler.queue.authority import return_active_claim_to_pending




class HostileIdentity:
    touched = 0

    def __str__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise AssertionError("identity text hook executed")

    def __repr__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise AssertionError("identity repr hook executed")

    def __format__(self, spec):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise AssertionError("identity format hook executed")


class HostilePath:
    touched = 0

    def __bool__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise AssertionError("path truthiness hook executed")

    def __str__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise AssertionError("path text hook executed")

    def __repr__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise AssertionError("path repr hook executed")

    def __format__(self, spec):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise AssertionError("path format hook executed")

    def __fspath__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise AssertionError("path filesystem hook executed")


def _return_constants_inside_exception(path: str, function_name: str) -> list[tuple[int, object]]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    constants: list[tuple[int, object]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == function_name:
            for child in ast.walk(node):
                if isinstance(child, ast.ExceptHandler):
                    for nested in ast.walk(child):
                        if isinstance(nested, ast.Return) and isinstance(nested.value, ast.Constant):
                            constants.append((nested.lineno, nested.value.value))
    return constants


def test_stage1874_enqueue_guard_exception_path_records_failed_closed_evidence_without_path_hooks():
    HostilePath.touched = 0
    records = []

    def record(where, exc, *, extra=None, fatal=False):
        records.append({"where": where, "extra": extra, "fatal": fatal, "exc_type": type(exc).__name__})
        return True

    with patch.object(admission_guard, "_process_queue_record_suppressed", record):
        allowed = process_queue_enqueue_guard(HostilePath(), {}, identity="raw:file:collector:0")

    assert allowed is False
    assert HostilePath.touched == 0
    assert records
    assert records[0]["where"] == "process_queue_enqueue_guard_failed_closed"
    assert records[0]["fatal"] is True
    extra = records[0]["extra"]
    assert extra["admission_allowed"] is False
    assert extra["process_queue_admission_failed_closed"] is True
    assert extra["failure_reason"] == "process_queue_enqueue_guard_exception"
    assert extra["final_json_must_record"] is True
    assert extra["checkpoint_must_record"] is True
    assert extra["replay_must_record"] is True
    assert extra["identity"] == "raw:file:collector:0"


def test_stage1874_return_active_claim_failure_records_failed_closed_path_evidence_without_hooks():
    HostilePath.touched = 0
    records = []

    def record(where, exc, *, extra=None, fatal=False):
        records.append({"where": where, "extra": extra, "fatal": fatal, "exc_type": type(exc).__name__})
        return True

    with patch.object(authority, "_process_queue_record_suppressed", record), patch.object(
        authority, "process_queue_quarantine_job", lambda *_args, **_kwargs: None
    ):
        returned = return_active_claim_to_pending(
            HostilePath(), HostilePath(), log_context="stage1874", telemetry_stage="stage1874_return_failed"
        )

    assert returned is False
    assert HostilePath.touched == 0
    assert records
    assert records[0]["where"] == "stage1874_return_failed"
    assert records[0]["fatal"] is True
    extra = records[0]["extra"]
    assert extra["active_returned_to_pending"] is False
    assert extra["process_queue_return_active_failed_closed"] is True
    assert extra["failure_reason"] == "return_active_claim_to_pending_failed"
    assert extra["final_json_must_record"] is True
    assert extra["checkpoint_must_record"] is True
    assert extra["replay_must_record"] is True
    assert extra["active_path_evidence"]["active_path_available"] is False
    assert extra["pending_path_evidence"]["pending_path_available"] is False


def test_stage1874_queue_admission_failure_paths_do_not_return_clean_sentinels_inside_exception_handlers():
    assert _return_constants_inside_exception(
        "Virus_Scan/scheduler/queue/admission_guard.py", "process_queue_enqueue_guard"
    ) == []
    assert _return_constants_inside_exception(
        "Virus_Scan/scheduler/queue/authority.py", "return_active_claim_to_pending"
    ) == []


def test_stage2181_enqueue_guard_invalid_identity_records_replayable_evidence_without_identity_hooks():
    HostileIdentity.touched = 0
    records = []

    def record(where, exc, *, extra=None, fatal=False):
        records.append({"where": where, "extra": extra, "fatal": fatal, "exc_type": type(exc).__name__})
        return True

    with patch.object(admission_guard, "_process_queue_record_suppressed", record):
        allowed = process_queue_enqueue_guard(Path("unused"), {}, identity=HostileIdentity())

    assert allowed is False
    assert HostileIdentity.touched == 0
    assert records
    assert records[0]["where"] == "process_queue_enqueue_guard_identity_rejected"
    assert records[0]["fatal"] is True
    extra = records[0]["extra"]
    assert extra["admission_allowed"] is False
    assert extra["process_queue_admission_failed_closed"] is True
    assert extra["failure_reason"] == "process_queue_enqueue_guard_identity_type_rejected"
    assert extra["identity"] == ""
    assert extra["identity_type"] == "HostileIdentity"
    assert extra["final_json_must_record"] is True
    assert extra["checkpoint_must_record"] is True
    assert extra["replay_must_record"] is True
