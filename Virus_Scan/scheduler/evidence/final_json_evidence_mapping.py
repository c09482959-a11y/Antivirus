"""Evidence-field collection helpers for scheduler final JSON projection."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable, Mapping
from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.evidence.final_json_exact_fields import (
    collect_exact_scheduler_evidence,
    exact_flag,
    exact_has_content,
    exact_mapping_items,
    exact_mapping_or_none,
    exact_mapping_value,
    first_exact_text,
)
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.evidence.record_collection import unsupported_scheduler_evidence_source
_EMPTY_EVIDENCE_VALUES: tuple[object, ...] = ()

@dataclass(frozen=True, slots=True)
class SchedulerEvidenceValuesDecision:
    values: tuple[object, ...]
    reason: str
    accepted: bool
    source_is_mapping: bool

_EXPLICIT_EVIDENCE_KEYS = (
    "scheduler_evidence",
    "scheduler_failure_evidence",
    "timeout_retry_evidence",
    "timeout_config_evidence",
    "retry_exhaustion_result_evidence",
    "worker_output_publication_evidence",
    "worker_lifecycle_evidence",
    "orphan_recovery_evidence",
)
def _collect_scheduler_evidence_sequence(
    found: list[object], sequence: tuple[object, ...], root_record: Mapping[str, object], stage: str
) -> None:
    found.extend(collect_exact_scheduler_evidence(sequence))
    for item in sequence:
        exact_item = exact_mapping_or_none(item)
        if exact_item is not None:
            found.extend(collect_scheduler_evidence_values_from_mapping(exact_item, root_record, default_stage_prefix=stage))


def _collect_scheduler_evidence_field(
    found: list[object], value: object, root_record: Mapping[str, object], stage: str
) -> None:
    if not exact_has_content(value):
        if value is not None and type(value) not in {dict, list, tuple, set, frozenset}:
            found.append(unsupported_scheduler_evidence_source(value))
        return
    exact_value = exact_mapping_or_none(value)
    if exact_value is not None:
        if looks_like_scheduler_evidence(exact_value):
            found.append(normalise_evidence_mapping(exact_value, root_record, default_stage=stage))
        else:
            found.extend(collect_exact_scheduler_evidence(exact_value))
            found.extend(collect_scheduler_evidence_values_from_mapping(exact_value, root_record, default_stage_prefix=stage))
        return
    if type(value) is list or type(value) is tuple:
        _collect_scheduler_evidence_sequence(found, tuple(value), root_record, stage)
    else:
        found.extend(collect_exact_scheduler_evidence(value))


def collect_scheduler_evidence_values_from_mapping_decision(
    source: Mapping[str, object],
    root_record: Mapping[str, object],
    *,
    default_stage_prefix: str = "scheduler",
) -> SchedulerEvidenceValuesDecision:
    """Return replayable state for explicit bounded scheduler evidence fields."""
    found: list[object] = []
    items = exact_mapping_items(source)
    if items is None:
        return SchedulerEvidenceValuesDecision(
            values=(unsupported_scheduler_evidence_source(source),),
            reason="unsupported_scheduler_evidence_mapping_source",
            accepted=False,
            source_is_mapping=False,
        )
    for key, value in items:
        if type(key) is not str:
            continue
        key_text = str.__str__(key)
        if key_text in _EXPLICIT_EVIDENCE_KEYS or key_text.endswith(("_evidence", "_evidence_records")):
            _collect_scheduler_evidence_field(found, value, root_record, key_text or default_stage_prefix)
    reason = "scheduler_evidence_fields_collected" if found else "scheduler_evidence_fields_absent"
    return SchedulerEvidenceValuesDecision(
        values=tuple(found) if found else _EMPTY_EVIDENCE_VALUES,
        reason=reason,
        accepted=True,
        source_is_mapping=True,
    )

def collect_scheduler_evidence_values_from_mapping(
    source: Mapping[str, object],
    root_record: Mapping[str, object],
    *,
    default_stage_prefix: str = "scheduler",
) -> tuple[object, ...]:
    """Return scheduler evidence from explicit bounded evidence fields."""
    return collect_scheduler_evidence_values_from_mapping_decision(
        source,
        root_record,
        default_stage_prefix=default_stage_prefix,
    ).values
def looks_like_scheduler_evidence(value: Mapping[str, object]) -> bool:
    """Return whether a scheduler mapping represents an event, not a passive budget."""
    record_requested = exact_flag(
        value,
        "final_json_must_record",
        "checkpoint_must_record",
        "replay_must_reproduce",
        "replay_must_record",
    )
    failure_flagged = exact_flag(
        value,
        "timeout_failure",
        "retry_failure",
        "worker_failure",
        "queue_failure",
        "scheduler_failure",
        "worker_killed",
        "worker_recovered",
        "retry_exhausted",
    )
    reason = first_exact_text(
        value,
        "error_category",
        "reason",
        "timeout_reason",
        "stall_reason",
        "inspection_error",
        "scheduler_failure_reason",
    )
    state = first_exact_text(value, "state", "scheduler_status", "status").lower()
    nonclean_state = bool(state) and state not in {
        "ok", "clean", "success", "passed", "complete", "completed",
    }
    return record_requested or failure_flagged or bool(reason) or nonclean_state

def normalise_evidence_mapping(value: Mapping[str, object], record: Mapping[str, object], *, default_stage: str) -> SchedulerEvidenceRecord:
    reason = first_exact_text(
        value,
        "error_category",
        "reason",
        "scheduler_failure_reason",
        "timeout_reason",
        "stall_reason",
        "inspection_error",
    ) or default_stage
    failure_state = exact_flag(value, "timeout_failure", "retry_failure", "queue_failure", "worker_failure", "inspection_error")
    return SchedulerEvidenceRecord(
        stage=first_exact_text(value, "stage") or default_stage,
        state=first_exact_text(value, "state") or ("failure" if failure_state else "degraded"),
        error_category=reason or default_stage,
        error_source=first_exact_text(value, "error_source") or "scheduler.final_json_projection",
        message=first_exact_text(value, "message") or reason or default_stage,
        context=materialize_scheduler_mapping(value),
        queue_id=first_exact_text(value, "queue_id") or first_exact_text(record, "queue_id", "queue_claim_id"),
        job_id=first_exact_text(value, "job_id") or first_exact_text(record, "job_id"),
        worker_id=first_exact_text(value, "worker_id") or first_exact_text(record, "worker_id"),
        path=first_exact_text(value, "path") or first_exact_text(record, "input_file_path", "path", "file"),
        retry_state_affected=exact_flag(value, "retry_state_affected", "retry_failure") or "retry" in reason,
        timeout_state_affected=(
            exact_flag(value, "timeout_state_affected", "timeout_failure", "inspection_error")
            or exact_mapping_value(value, "timeout_budget") is not None
            or exact_mapping_value(value, "stall_budget") is not None
            or "timeout" in reason
            or "stall" in reason
            or "stall" in first_exact_text(value, "stage", "error_source", "action")
        ),
        final_json_must_record=exact_flag(value, "final_json_must_record", default=True),
        checkpoint_must_record=exact_flag(value, "checkpoint_must_record", default=True),
        replay_must_record=exact_flag(value, "replay_must_record", default=exact_flag(value, "replay_must_reproduce", default=True)),
        fatal=exact_flag(value, "fatal"),
    )

def dedupe_evidence(records: Iterable[SchedulerEvidenceRecord]) -> tuple[SchedulerEvidenceRecord, ...]:
    out: list[SchedulerEvidenceRecord] = []
    seen: set[tuple[str, str, str, str, str, str]] = set()
    for record in records:
        key = (record.stage, record.error_category, record.queue_id, record.job_id, record.worker_id, record.path)
        if key not in seen:
            seen.add(key)
            out.append(record)
    return tuple(out)

__all__ = (
    "SchedulerEvidenceValuesDecision",
    "collect_scheduler_evidence_values_from_mapping",
    "collect_scheduler_evidence_values_from_mapping_decision",
    "dedupe_evidence",
    "looks_like_scheduler_evidence",
    "normalise_evidence_mapping",
)
