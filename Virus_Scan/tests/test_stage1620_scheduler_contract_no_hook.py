from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from Virus_Scan.scheduler.contracts.phase_output import SchedulerPhaseOutput
from Virus_Scan.scheduler.contracts.queue_claim import QueueClaim
from Virus_Scan.scheduler.contracts.queue_snapshot import QueueIntegrityResult, QueueMergeResult, QueueRecoveryResult, QueueSnapshot
from Virus_Scan.scheduler.contracts.replay_result import ReplayComparisonResult, ReplaySnapshot
from Virus_Scan.scheduler.contracts.retry_result import RetryDecision, RetryExhaustionResult
from Virus_Scan.scheduler.contracts.scheduler_result import SchedulerResult
from Virus_Scan.scheduler.contracts.timeout_result import TimeoutResult
from Virus_Scan.scheduler.contracts.worker_result import WorkerIdentity, WorkerResult, WorkerSnapshot


class HostileText:
    touched = 0

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("str hook touched")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("repr hook touched")

    def __format__(self, format_spec):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("format hook touched")


class HostileNumber:
    touched = 0

    def __int__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("int hook touched")

    def __float__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("float hook touched")

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("bool hook touched")


class HostileSequence:
    touched = 0

    def __iter__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("iter hook touched")

    def __len__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("len hook touched")


class HostileMappingLike:
    touched = 0

    def get(self, key, default=None):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("get hook touched")

    def items(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("items hook touched")

    def __iter__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("iter hook touched")

    def __len__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("len hook touched")


def _reset() -> None:
    HostileText.touched = 0
    HostileNumber.touched = 0
    HostileSequence.touched = 0
    HostileMappingLike.touched = 0


def _assert_untouched() -> None:
    assert HostileText.touched == 0
    assert HostileNumber.touched == 0
    assert HostileSequence.touched == 0
    assert HostileMappingLike.touched == 0


def test_stage1620_queue_claim_timeout_and_retry_contracts_reject_hostile_scalars_without_hooks() -> None:
    _reset()

    claim = cast(Any, QueueClaim)(job_id=HostileText(), file=HostileText(), worker_id=HostileText(), generation=HostileNumber(), attempt=HostileNumber())
    timeout = cast(Any, TimeoutResult)(timed_out=HostileNumber(), elapsed_sec=HostileNumber(), budget_sec=HostileNumber(), stage=HostileText(), evidence=HostileSequence())
    retry = cast(Any, RetryDecision)(retry_allowed=HostileNumber(), exhausted=HostileNumber(), attempt=HostileNumber(), max_attempts=HostileNumber(), reason=HostileText(), evidence=HostileSequence())
    exhausted = cast(Any, RetryExhaustionResult)(exhausted=HostileNumber(), job_id=HostileText(), reason=HostileText(), evidence=HostileSequence())

    _assert_untouched()
    assert claim.job_id == ""
    assert claim.generation == 0
    claim_rejections = claim.as_dict()["metadata"]["queue_claim_contract_rejections"]
    assert {item["reason"] for item in claim_rejections} >= {"scheduler_contract_text_rejected", "scheduler_contract_int_rejected"}
    assert timeout.timed_out is False
    assert timeout.elapsed_sec == 0.0
    assert retry.retry_allowed is False
    assert retry.attempt == 0
    assert exhausted.exhausted is True
    timeout_reasons = {item["reason"] for item in timeout.as_dict()["evidence"]}
    retry_reasons = {item["reason"] for item in retry.as_dict()["evidence"]}
    exhausted_reasons = {item["reason"] for item in exhausted.as_dict()["evidence"]}
    assert "scheduler_contract_float_rejected" in timeout_reasons
    assert "scheduler_contract_bool_rejected" in retry_reasons
    assert "scheduler_contract_text_rejected" in exhausted_reasons


def test_stage1620_queue_worker_replay_and_scheduler_result_contracts_reject_hooks() -> None:
    _reset()

    queue = cast(Any, QueueSnapshot)(phase=HostileText(), pending=HostileNumber(), active=HostileNumber(), done=HostileNumber(), failed=HostileNumber(), evidence=HostileSequence())
    integrity = cast(Any, QueueIntegrityResult)(ok=HostileNumber(), snapshot=queue, failures=HostileSequence())
    recovery = cast(Any, QueueRecoveryResult)(recovered=HostileNumber(), orphaned=HostileNumber(), evidence=HostileSequence())
    merge = cast(Any, QueueMergeResult)(missing_results=HostileSequence(), evidence=HostileSequence())
    identity = cast(Any, WorkerIdentity)(worker_id=HostileText(), pid=HostileNumber(), generation=HostileNumber())
    worker_snapshot = cast(Any, WorkerSnapshot)(live_count=HostileNumber(), workers=HostileSequence(), evidence=HostileSequence())
    worker_result = cast(Any, WorkerResult)(identity=identity, success=HostileNumber(), failures=HostileSequence())
    replay = cast(Any, ReplaySnapshot)(replay_id=HostileText(), records=HostileSequence(), evidence=HostileSequence())
    comparison = cast(Any, ReplayComparisonResult)(matched=HostileNumber(), expected=replay, actual=ReplaySnapshot(), mismatches=HostileSequence())
    scheduler = cast(Any, SchedulerResult)(status=HostileText(), evidence=())

    _assert_untouched()
    assert queue.phase == "unknown"
    assert queue.pending == 0
    assert integrity.ok is False
    assert recovery.recovered == 0
    assert merge.as_dict()["missing_results"][0]["reason"] == "scheduler_contract_sequence_rejected"
    assert identity.worker_id == ""
    assert worker_snapshot.live_count == 0
    assert worker_result.success is False
    assert replay.replay_id == ""
    assert comparison.matched is False
    assert scheduler.status == "ok"
    assert "scheduler_contract_text_rejected" in {item["reason"] for item in queue.as_dict()["evidence"]}
    assert "scheduler_contract_int_rejected" in {item["reason"] for item in worker_snapshot.as_dict()["evidence"]}
    assert scheduler.as_dict()["evidence"][0]["error_category"] == "scheduler_contract_field_rejected"


def test_stage1620_contract_from_mapping_paths_do_not_call_mapping_or_iter_hooks() -> None:
    _reset()
    hostile = HostileMappingLike()

    claim = cast(Any, QueueClaim.from_mapping)(hostile)
    timeout = cast(Any, TimeoutResult.from_mapping)(hostile)
    retry = cast(Any, RetryDecision.from_mapping)(hostile)
    exhausted = cast(Any, RetryExhaustionResult.from_mapping)(hostile)
    queue = cast(Any, QueueSnapshot.from_mapping)(hostile)
    integrity = cast(Any, QueueIntegrityResult.from_mapping)(hostile)
    recovery = cast(Any, QueueRecoveryResult.from_mapping)(hostile)
    merge = cast(Any, QueueMergeResult.from_mapping)(hostile)
    worker_identity = cast(Any, WorkerIdentity.from_mapping)(hostile)
    worker_snapshot = cast(Any, WorkerSnapshot.from_mapping)(hostile)
    worker_result = cast(Any, WorkerResult.from_mapping)(hostile)
    replay = cast(Any, ReplaySnapshot.from_mapping)(hostile)
    comparison = cast(Any, ReplayComparisonResult.from_mapping)(hostile)
    scheduler = cast(Any, SchedulerResult.from_mapping)(hostile)

    _assert_untouched()
    assert claim.as_dict()["metadata"]["queue_claim_contract_rejections"][0]["reason"] == "scheduler_contract_mapping_rejected"
    assert timeout.as_dict()["stage"] == "timeout"
    assert retry.as_dict()["retry_allowed"] is False
    assert exhausted.as_dict()["exhausted"] is True
    assert queue.as_dict()["phase"] == "unknown"
    assert integrity.as_dict()["snapshot"]["phase"] == "unknown"
    assert recovery.as_dict()["recovered"] == 0
    assert merge.as_dict()["merged"] == {}
    assert worker_identity.as_dict()["worker_id"] == ""
    assert worker_snapshot.as_dict()["live_count"] == 0
    assert worker_result.as_dict()["identity"]["worker_id"] == ""
    assert replay.as_dict()["replay_id"] == ""
    assert comparison.as_dict()["matched"] is False
    assert scheduler.as_dict()["status"] == "ok"


def test_stage1620_phase_output_contract_rejects_hostile_envelope_fields_without_hooks() -> None:
    _reset()
    payload = QueueSnapshot()

    output = cast(Any, SchedulerPhaseOutput)(
        phase=HostileText(),
        domain=HostileText(),
        status=HostileText(),
        sequence=HostileNumber(),
        payload=payload,
        evidence=(),
    )

    _assert_untouched()
    decoded = output.as_dict()
    assert decoded["phase"] == "scheduler"
    assert decoded["domain"] == "scheduler"
    assert decoded["status"] == "ok"
    assert decoded["sequence"] == 0
    assert {record["context"]["reason"] for record in decoded["evidence"]} >= {"scheduler_contract_text_rejected", "scheduler_contract_int_rejected"}



def test_stage1827_scheduler_contract_errors_do_not_reintroduce_fstring_materialization() -> None:
    contracts_root = Path(__file__).resolve().parents[1] / "scheduler" / "contracts"
    phase_output_source = (contracts_root / "phase_output.py").read_text(encoding="utf-8")
    scheduler_result_source = (contracts_root / "scheduler_result.py").read_text(encoding="utf-8")

    assert 'f"SchedulerPhaseOutput payload must be one of: {allowed}"' not in phase_output_source
    assert 'f"unknown SchedulerPhaseOutput payload_type: {payload_type_text}"' not in phase_output_source
    assert 'f"SchedulerResult {name} requires {expected_type.__name__}"' not in scheduler_result_source
