"""Single bounded scheduler-result retention owner."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.retained_scan_result import build_retained_scan_result
from Virus_Scan.models.replay.payload import result_learning_payload
from Virus_Scan.orchestration.direct_audit_projection import (
    DirectAuditProjectionContext,
    project_direct_audit_record,
)
from Virus_Scan.publication.api.retained_result import build_retained_publication_record
from Virus_Scan.scheduler.api.final_json import attach_scheduler_final_json_fields


@dataclass(frozen=True, slots=True)
class SchedulerResultRetentionContext:
    """Immutable publication context shared by serial and process schedulers."""

    scheduler_mode: str
    requested_engine: str
    yara_enabled: bool
    def __post_init__(self) -> None:
        DirectAuditProjectionContext(
            scheduler_mode=self.scheduler_mode,
            requested_engine=self.requested_engine,
            yara_enabled=self.yara_enabled,
        )

    def direct_audit_context(self) -> DirectAuditProjectionContext:
        return DirectAuditProjectionContext(
            scheduler_mode=self.scheduler_mode,
            requested_engine=self.requested_engine,
            yara_enabled=self.yara_enabled,
        )




def _terminal_failure_bypasses_retention(result: object) -> bool:
    """Keep bounded terminal failure records on the established finalization path."""
    if type(result) is not dict:
        return True
    classification = dict.get(result, "classification", dict.get(result, "class"))
    if type(classification) is str and str.lower(classification) == "error":
        return True
    queue_failure = dict.get(result, "queue_failure")
    return type(queue_failure) is bool and queue_failure


@dataclass(frozen=True, slots=True)
class SchedulerResultRetainer:
    """Callable owner that materializes one bounded retained scheduler result."""

    context: SchedulerResultRetentionContext

    def __call__(self, path: object, result: object) -> object:
        if _terminal_failure_bypasses_retention(result):
            return result
        replay_payload = result_learning_payload(result)
        output_path, audited = project_direct_audit_record(
            path,
            result,
            self.context.direct_audit_context(),
        )
        scheduled = attach_scheduler_final_json_fields(audited)
        compact = build_retained_publication_record(scheduled, output_path)
        return build_retained_scan_result(compact, replay_payload)


def build_scheduler_result_retainer(
    *,
    scheduler_mode: str,
    requested_engine: str,
    yara_enabled: bool,
) -> SchedulerResultRetainer:
    """Build the one production retainer for a scheduler run."""
    return SchedulerResultRetainer(
        SchedulerResultRetentionContext(
            scheduler_mode=scheduler_mode,
            requested_engine=requested_engine,
            yara_enabled=yara_enabled,
        )
    )


__all__ = (
    "SchedulerResultRetainer",
    "SchedulerResultRetentionContext",
    "build_scheduler_result_retainer",
)
