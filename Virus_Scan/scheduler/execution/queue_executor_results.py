from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from Virus_Scan.scanners.api.raw_queue_contracts import (
    RawQueueScanResultDependencies,
    build_global_raw_scan_result,
)
from Virus_Scan.scheduler.execution.queue_scan_outcome import (
    GlobalRawQueueScanOutcome,
    raw_queue_scan_completed,
)
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_evidence_path,
)

if TYPE_CHECKING:
    from Virus_Scan.scheduler.execution.queue_executor_contracts import (
        GlobalRawQueueScanDependencies,
        RawQueueRecord,
    )


class _RawQueueScanPlanView(Protocol):
    @property
    def file_id(self) -> str:
        ...

    @property
    def identity(self) -> RawQueueRecord:
        ...

    @property
    def effective_stage(self) -> str:
        ...


def completed_raw_scan_outcome(
    path: object,
    plan: _RawQueueScanPlanView,
    accum: RawQueueRecord,
    deps: GlobalRawQueueScanDependencies,
) -> GlobalRawQueueScanOutcome:
    result = build_global_raw_scan_result(
        path=scheduler_evidence_path(path, field_name="raw_queue_path"),
        file_id=plan.file_id,
        accum=accum,
        identity=plan.identity,
        effective_stage=plan.effective_stage,
        deps=RawQueueScanResultDependencies(
            ordered_unique_tags=deps.ordered_unique_tags,
            finalize_tag_evidence_generation=deps.finalize_tag_evidence_generation,
            apply_integrity_tags=deps.apply_integrity_tags,
            normalize_tags=deps.normalize_tags,
            staged_enrichment_score=deps.staged_enrichment_score,
            scanner_degraded_tags=deps.scanner_degraded_tags,
            mark_raw_integrity_failure=deps.mark_raw_integrity_failure,
            remember_scan_evidence=deps.remember_scan_evidence,
            normalize_yara_hits=deps.normalize_yara_hits,
            set_scan_integrity=deps.set_scan_integrity,
        ),
    )
    return raw_queue_scan_completed(result)


__all__ = ("completed_raw_scan_outcome",)
