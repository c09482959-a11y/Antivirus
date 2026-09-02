"""Replay projection failure evidence ownership."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import (
    exact_text_or_none,
    materialize_json_no_hook,
    no_hook_type_name,
    unsupported_value_evidence,
)
from Virus_Scan.scheduler.contracts.replay_result import ReplayComparisonResult, ReplaySnapshot
from Virus_Scan.scheduler.internal.exception_projection import scheduler_exception_text

REPLAY_PROJECTION_EXCEPTIONS = (RuntimeError, TypeError, ValueError, OverflowError)

@dataclass(frozen=True, slots=True)
class ReplayRawRecordsDecision:
    """Replayable decision for raw replay-record materialization."""

    records: tuple[Mapping[str, object], ...]
    accepted: bool
    reason: str
    source_type: str


def _raw_replay_records_decision(raw_results: object) -> ReplayRawRecordsDecision:
    if raw_results is None:
        return ReplayRawRecordsDecision(
            ({
                "record_index": 0,
                "missing_replay_raw_records": True,
                "replay_raw_records_unavailable_reason": "missing_replay_raw_records",
            },),
            False,
            "missing_replay_raw_records",
            "NoneType",
        )
    items = raw_results if type(raw_results) in {list, tuple} else (raw_results,)
    records: list[Mapping[str, object]] = []
    accepted = True
    for index, item in enumerate(items):
        materialized = materialize_json_no_hook(
            item,
            context="scheduler_replay_projection_raw_record",
            max_depth=8,
            max_items=128,
        )
        if type(materialized) is dict:
            record = dict(materialized)
            record.setdefault("record_index", index)
            records.append(record)
        else:
            accepted = False
            records.append({
                "record_index": index,
                "malformed_record": unsupported_value_evidence(
                    item,
                    context="scheduler_replay_projection_raw_record",
                    reason="non_materializable_scheduler_replay_raw_record",
                ),
            })
    reason = "accepted" if accepted else "non_materializable_scheduler_replay_raw_record"
    return ReplayRawRecordsDecision(tuple(records), accepted, reason, no_hook_type_name(raw_results))


def _projection_mismatch(side: str, exc: BaseException) -> Mapping[str, object]:
    side_name = exact_text_or_none(side) or "unknown"
    return {
        "mismatch_type": "projection_failure",
        "side": side_name,
        "error_category": "replay_projection_failure",
        "error_source": no_hook_type_name(exc),
        "message": scheduler_exception_text(exc, missing_text="scheduler replay projection failed"),
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_record": True,
    }


def _failure_snapshot(side: str, exc: BaseException | None, raw_results: object) -> ReplaySnapshot:
    replay_id = exact_text_or_none(side) or "unknown"
    if exc is None:
        return ReplaySnapshot(replay_id=replay_id, records=(), evidence=())
    mismatch = _projection_mismatch(side, exc)
    return ReplaySnapshot(
        replay_id=replay_id,
        records=_raw_replay_records_decision(raw_results).records,
        evidence=(mismatch,),
    )


def build_replay_projection_failure_comparison(
    *,
    expected_error: BaseException | None = None,
    expected_raw_results: object = None,
    actual_error: BaseException | None = None,
    actual_raw_results: object = None,
) -> ReplayComparisonResult:
    mismatches: list[Mapping[str, object]] = []
    if expected_error is not None:
        mismatches.append(_projection_mismatch("expected", expected_error))
    if actual_error is not None:
        mismatches.append(_projection_mismatch("actual", actual_error))
    return ReplayComparisonResult(
        matched=False,
        expected=_failure_snapshot("expected", expected_error, expected_raw_results),
        actual=_failure_snapshot("actual", actual_error, actual_raw_results),
        mismatches=tuple(mismatches),
    )


def build_replay_projection_failure_result(
    side: str,
    exc: BaseException,
    raw_results: object,
) -> ReplayComparisonResult:
    if (exact_text_or_none(side) or "unknown") == "actual":
        return build_replay_projection_failure_comparison(actual_error=exc, actual_raw_results=raw_results)
    return build_replay_projection_failure_comparison(expected_error=exc, expected_raw_results=raw_results)


__all__ = (
    "REPLAY_PROJECTION_EXCEPTIONS",
    "build_replay_projection_failure_comparison",
    "build_replay_projection_failure_result",
)
