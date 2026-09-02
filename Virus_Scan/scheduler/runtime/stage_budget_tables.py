"""Runtime-owned scheduler stage-budget table lookup and evidence."""
from __future__ import annotations

from types import MappingProxyType


from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_type_name,
)
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.api import record_suppressed_failure, scheduler_runtime_state
from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_text
from Virus_Scan.scheduler.queue.admission import classify_workload

_NO_STAGE_TABLE = None

def stage_class_for_task(name: object) -> object:
    stage_name, reason = scheduler_text(
        name,
        replacement_text="",
        unsupported_reason="stage_budget_task_name_rejected",
    )
    if reason:
        stage_name = "unknown"
    cls = classify_workload(stage=stage_name)
    if cls == 'media':
        cls = 'image'
    return cls if cls in {'archive', 'dotnet', 'yara', 'image', 'raw', 'generic'} else 'generic'


def stage_budget_failure_evidence(stage_name: object, category: object, message: object, *, exception_type: object="") -> dict[str, object]:
    cls = stage_class_for_task(stage_name)
    category_text, category_reason = scheduler_text(
        category,
        replacement_text="stage_budget_unavailable",
        unsupported_reason="stage_budget_category_rejected",
    )
    message_text, message_reason = scheduler_text(
        message,
        replacement_text=category_text,
        unsupported_reason="stage_budget_message_rejected",
    )
    stage_text, stage_reason = scheduler_text(
        stage_name,
        replacement_text="",
        unsupported_reason="stage_budget_stage_name_rejected",
    )
    exception_text, exception_reason = scheduler_text(
        exception_type,
        replacement_text="",
        unsupported_reason="stage_budget_exception_type_rejected",
    )
    boundary_reasons = tuple(
        reason
        for reason in (
            category_reason,
            message_reason,
            stage_reason,
            exception_reason,
        )
        if reason
    )
    return SchedulerEvidenceRecord(
        stage="stage_budget",
        state="failed",
        error_category=category_text,
        error_source="scheduler.runtime.stage_budget",
        message=message_text,
        context={
            "stage_name": stage_text,
            "stage_class": cls,
            "exception_type": exception_text,
            "boundary_reasons": boundary_reasons,
        },
        final_json_must_record=True,
        checkpoint_must_record=True,
        replay_must_record=True,
        fatal=False,
    ).as_dict()


def record_stage_budget_failure(evidence: object, exc: BaseException | None = None) -> None:
    try:
        evidence_items = no_hook_mapping_items(evidence)
        if evidence_items is None:
            raise ValueError("stage_budget_failure_evidence_rejected")
        evidence_snapshot = dict(evidence_items)
        category, _category_reason = scheduler_text(
            dict.get(evidence_snapshot, "error_category"),
            replacement_text="stage_budget_failure",
        )
        message, _message_reason = scheduler_text(
            dict.get(evidence_snapshot, "message"),
            replacement_text=category,
        )
        failure = exc if exc is not None else RuntimeError(message)
        record_suppressed_failure(
            category,
            failure,
            domain="scheduler",
            context=evidence_snapshot,
        )
    except RECOVERABLE_RUNTIME_ERRORS as reporting_exc:
        _ = reporting_exc


def stage_tables_snapshot() -> object:
    snapshot = None
    tables = None
    try:
        tables = scheduler_runtime_state().stage_tables_snapshot()
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        evidence = stage_budget_failure_evidence(
            "generic",
            "stage_budget_unavailable",
            "runtime scheduler stage tables snapshot unavailable",
            exception_type=no_hook_type_name(exc),
        )
        record_stage_budget_failure(evidence, exc)
    else:
        table_items = no_hook_mapping_items(tables)
        if table_items is None:
            evidence = stage_budget_failure_evidence(
                "generic",
                "stage_budget_corrupt",
                "runtime scheduler stage tables snapshot is not a mapping",
                exception_type=no_hook_type_name(tables),
            )
            record_stage_budget_failure(evidence)
        else:
            snapshot = MappingProxyType(dict(table_items))
    return snapshot


def stage_table(kind: str, stage_name: object) -> object:
    tables = stage_tables_snapshot()
    if tables is None:
        return _NO_STAGE_TABLE
    tables_items = no_hook_mapping_items(tables)
    table_map = dict(tables_items) if tables_items is not None else {}
    table_items = no_hook_mapping_items(dict.get(table_map, kind))
    if table_items is not None:
        return MappingProxyType(dict(table_items))
    kind_text, _kind_reason = scheduler_text(kind, replacement_text="unknown")
    evidence = stage_budget_failure_evidence(
        stage_name,
        "stage_budget_corrupt",
        "runtime scheduler " + kind_text + " table is not a mapping",
        exception_type="unknown",
    )
    record_stage_budget_failure(evidence)
    return _NO_STAGE_TABLE


__all__ = (
    "record_stage_budget_failure",
    "stage_budget_failure_evidence",
    "stage_class_for_task",
    "stage_table",
    "stage_tables_snapshot",
)
