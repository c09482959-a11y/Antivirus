"""No-hook process-queue completion evidence attachment."""
from __future__ import annotations

from typing import Mapping, cast

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.evidence.record_collection import collect_scheduler_evidence
from Virus_Scan.scheduler.internal.immutable_output_support import (
    FrozenSchedulerMapping,
    frozen_scheduler_items_decision,
    unsupported_scheduler_value_evidence,
)
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_int


def _scheduler_mapping_get(value: object, key: str, default: object = None) -> tuple[object, str]:
    if type(value) is dict:
        return dict.get(value, key, default), ""
    if type(value) is FrozenSchedulerMapping:
        frozen_decision = frozen_scheduler_items_decision(value)
        for item_key, item_value in frozen_decision.items if frozen_decision.accepted else ():
            if item_key == key:
                return item_value, ""
        return default, ""
    return default, "scheduler_mapping_rejected"


def _worker_exit_evidence_unavailable(value: object, *, reason: str) -> dict[str, object]:
    evidence = unsupported_scheduler_value_evidence(value, field_name="worker_exit_evidence")
    evidence["process_queue_worker_exit_evidence_unavailable"] = True
    evidence["worker_exit_evidence_rejection_reason"] = reason
    evidence["worker_exit_evidence_type"] = no_hook_type_name(value)
    evidence["error_category"] = "scheduler_worker_exit_evidence_unavailable"
    evidence["error_source"] = "scheduler.orchestration.process_queue_completion"
    return evidence


def collect_nonclean_worker_exit_evidence(worker_exit_evidence: tuple[Mapping[str, object], ...]) -> tuple[dict[str, object], ...]:
    """Return deterministic non-clean worker-exit evidence without caller hooks."""
    collected: list[dict[str, object]] = []
    if type(worker_exit_evidence) is not tuple:
        return (_worker_exit_evidence_unavailable(worker_exit_evidence, reason="worker_exit_evidence_sequence_rejected"),)
    for evidence in worker_exit_evidence:
        evidence_is_failure = True
        if type(evidence) in {dict, FrozenSchedulerMapping}:
            evidence_is_failure = False
            timed_out_value, timed_out_reason = _scheduler_mapping_get(evidence, "worker_wait_timed_out", False)
            timed_out, _reason = scheduler_bool(timed_out_value, default=False)
            if timed_out or timed_out_reason:
                evidence_is_failure = True
            unsupported_value, unsupported_reason = _scheduler_mapping_get(
                evidence,
                "worker_exit_result_unsupported",
                False,
            )
            unsupported, _unsupported_bool_reason = scheduler_bool(unsupported_value, default=False)
            if unsupported or unsupported_reason:
                evidence_is_failure = True
            markers, markers_reason = _scheduler_mapping_get(evidence, "worker_failure_markers", ())
            has_markers = True
            if type(markers) in {tuple, list, set, frozenset}:
                has_markers = len(cast("tuple[object, ...]", markers)) > 0
            elif markers is None:
                has_markers = False
            elif type(markers) is str:
                has_markers = str.__str__(markers) != ""
            if markers_reason or has_markers:
                evidence_is_failure = True
            status_value, status_reason = _scheduler_mapping_get(evidence, "worker_exit_status", 0)
            status, status_materialization_reason = scheduler_int(status_value, default=-1)
            if status_reason or status_materialization_reason or status < 0 or status == 4:
                evidence_is_failure = True
        if evidence_is_failure:
            if type(evidence) in {dict, FrozenSchedulerMapping}:
                materialized = materialize_scheduler_mapping(evidence)
                if type(materialized) is dict:
                    collected.append(materialized)
                else:
                    collected.append(
                        _worker_exit_evidence_unavailable(
                            evidence,
                            reason="worker_exit_evidence_materialization_failed",
                        )
                    )
            else:
                collected.append(
                    _worker_exit_evidence_unavailable(evidence, reason="worker_exit_evidence_mapping_rejected")
                )
    return tuple(collected)


def attach_worker_exit_evidence_to_merged_results(
    merged: dict[str, object],
    worker_exit_evidence: tuple[Mapping[str, object], ...],
) -> None:
    """Attach non-clean worker-exit evidence to exact dict queue results."""
    failure_evidence = collect_nonclean_worker_exit_evidence(worker_exit_evidence)

    if not failure_evidence:
        return
    if type(merged) is not dict:
        return
    for result in dict.values(merged):
        if type(result) is not dict:
            continue
        integrity_source = dict.get(result, "scan_integrity")
        integrity = dict(integrity_source) if type(integrity_source) is dict else {}
        integrity["process_queue_worker_exit_evidence"] = failure_evidence
        result["scan_integrity"] = integrity


def attach_scheduler_evidence_to_merged_results(
    merged: dict[str, object],
    evidence_sources: tuple[object, ...],
) -> None:
    """Attach immutable scheduler evidence records to exact dict scan results."""
    if type(merged) is not dict:
        return
    evidence = tuple(record.as_dict() for record in collect_scheduler_evidence(evidence_sources))
    if not evidence:
        return
    for result in dict.values(merged):
        if type(result) is not dict:
            continue
        existing = dict.get(result, "scheduler_evidence")
        existing_records: tuple[object, ...]
        if type(existing) is list:
            existing_records = tuple(existing)
        elif type(existing) is tuple:
            existing_records = existing
        else:
            existing_records = ()
        result["scheduler_evidence"] = existing_records + evidence


__all__ = (
    "attach_scheduler_evidence_to_merged_results",
    "attach_worker_exit_evidence_to_merged_results",
    "collect_nonclean_worker_exit_evidence",
)
