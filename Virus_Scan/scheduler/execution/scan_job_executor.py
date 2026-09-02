"""Canonical raw-stage job execution ownership for the process queue.

This module owns the claim -> execute -> accumulator append -> finish boundary
for a single raw-stage helper job. Keeping it inside execution ownership prevents
that orchestrator from also owning child execution failure classification.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol, TypeAlias, TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_item_value
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.execution.scan_job_executor_decisions import (
    raw_recovery_text_decision,
    raw_stage_job_predicate_decision,
    raw_stage_job_unclaimed_decision,
)
from Virus_Scan.scheduler.execution.scan_job_executor_support import (
    RawFailureInfoOwner,
    raw_failure_info,
    raw_job_attempt,
    raw_job_text,
)
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_value_snapshot

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping


RawJobItems: TypeAlias = tuple[tuple[object, object], ...]
RawJobSnapshot: TypeAlias = dict[str, object]
RawFailureInfo: TypeAlias = dict[str, object]
RawResultPayload: TypeAlias = dict[str, object]


class RawAccumulatorStore(Protocol):
    def append(self, payload: object) -> object:
        ...


class RawExecutionEnvelope(Protocol):
    error: str

    def to_accumulator_record(self) -> object:
        ...


@dataclass(frozen=True)
class RawQueueJobExecutionDependencies(RawFailureInfoOwner):
    claim_matching: Callable[..., tuple[Mapping[str, object] | None, object]]
    execute_stage_job: Callable[[Mapping[str, object]], object]
    envelope_from_raw_result: Callable[[RawJobSnapshot, RawResultPayload], RawExecutionEnvelope]
    result_has_infra_error: Callable[[object], bool]
    classify_recovery: Callable[..., object]
    default_failure_info: Callable[..., RawFailureInfo]
    prepare_raw_retry: Callable[[object, Mapping[str, object], object], bool]
    accumulator_store: Callable[[object, object], RawAccumulatorStore]
    record_suppressed: Callable[[str, BaseException], object]
    safe_exception_info: Callable[..., RawFailureInfo]
    finish_job: Callable[..., object]
    recoverable_exceptions: tuple[type[BaseException], ...]


def process_one_raw_stage_job(queue_dir: object, *, only_file_id: str | None = None, deps: RawQueueJobExecutionDependencies) -> bool:
    """Claim and process one raw-stage job with explicit failure semantics."""

    def pred(job: Mapping[str, object]) -> bool:
        return raw_stage_job_predicate_decision(job, only_file_id=only_file_id).eligible

    job, claim_path = deps.claim_matching(queue_dir, pred, worker_id="umige_raw")
    job_items = no_hook_mapping_items(job)
    if job_items is None:
        job_snapshot: RawJobSnapshot | None = None
        job_boundary: RawFailureInfo = {
            "raw_job_unavailable": unsupported_scheduler_value_evidence(job, field_name="raw_stage_job"),
        }
    else:
        job_snapshot = {
            key: scheduler_value_snapshot(value, field_name=key)
            for key, value in job_items
            if type(key) is str
        }
        job_boundary = {}
    if job is None:
        return raw_stage_job_unclaimed_decision().processed
    if job_snapshot is None:
        unavailable_failure_info = deps.default_failure_info(
            stage="raw_stage_job_unavailable",
            exception_type="RawStageJobUnavailable",
            error="raw stage job rejected without caller hooks",
            worker_pid=os.getpid(),
            attempt=0,
            extra=job_boundary,
        )
        deps.finish_job(queue_dir, claim_path, ok=False, error_info=unavailable_failure_info, job=None)
        return True

    ok = False
    failure_info: RawFailureInfo | None = None
    try:
        result = deps.execute_stage_job(job_snapshot)
        result_payload = result if type(result) is dict else {"result": result}
        envelope = deps.envelope_from_raw_result(job_snapshot, result_payload)
        if deps.result_has_infra_error(result if type(result) is dict else result_payload):
            infrastructure_error = "raw stage returned infrastructure error"
            decision = deps.classify_recovery(
                envelope.error or infrastructure_error,
                stage=raw_job_text(scheduler_mapping_item_value(job_items, "collector"), default_text="raw_stage", field_name="collector")[0],
            )
            decision_reason = raw_recovery_text_decision(decision, field_name="reason").text
            failure_info = deps.default_failure_info(
                stage=raw_job_text(scheduler_mapping_item_value(job_items, "collector"), default_text="raw_stage", field_name="collector")[0],
                exception_type="RawStageInfrastructureError",
                error=(
                    raw_job_text(
                        scheduler_mapping_item_value(no_hook_mapping_items(result_payload), "error"),
                        default_text="",
                        field_name="result_error",
                    )[0]
                    or decision_reason
                    or infrastructure_error
                ),
                worker_pid=os.getpid(),
                attempt=raw_job_attempt(scheduler_mapping_item_value(job_items, "attempt", 0))[0],
                extra={
                    "collector": scheduler_mapping_item_value(job_items, "collector"),
                    "seq": scheduler_mapping_item_value(job_items, "seq"),
                    "file": scheduler_mapping_item_value(job_items, "file"),
                    "recovery_action": raw_recovery_text_decision(decision, field_name="action").text,
                },
            )
            if deps.prepare_raw_retry(queue_dir, job_snapshot, result_payload):
                ok = True
                return True
        deps.accumulator_store(queue_dir, scheduler_mapping_item_value(job_items, "file_id")).append(envelope.to_accumulator_record())
        ok = True
        return True
    except (OSError, RuntimeError, TypeError, ValueError, TimeoutError) as exc:
        deps.record_suppressed("raw_process_one_job_failed_closed", exc)
        failure_info = raw_failure_info(
            deps,
            exc,
            stage_value=scheduler_mapping_item_value(job_items, "collector"),
            attempt_value=scheduler_mapping_item_value(job_items, "attempt", 0),
            default_stage="raw_stage_exception",
        )
        ok = False
    except deps.recoverable_exceptions as exc:  # bounded by raw queue contract; never silent
        deps.record_suppressed("raw_process_one_job_unexpected_failure", exc)
        failure_info = raw_failure_info(
            deps,
            exc,
            stage_value=scheduler_mapping_item_value(job_items, "collector"),
            attempt_value=scheduler_mapping_item_value(job_items, "attempt", 0),
            default_stage="raw_stage_unexpected_exception",
        )
        ok = False
    finally:
        deps.finish_job(queue_dir, claim_path, ok=ok, error_info=failure_info, job=job_snapshot)
    return True
