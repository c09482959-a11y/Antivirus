"""Immutable scheduler evidence record contracts."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from Virus_Scan.scheduler.contracts.evidence_record_support import (
    first_scheduler_mapping_value,
    merge_field_issue,
    scheduler_bool_field,
    scheduler_context_with_issues,
    scheduler_mapping_items,
    scheduler_mapping_value,
    scheduler_text_field,
)
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping, unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.internal.immutable_snapshots import immutable_snapshot_mapping


@dataclass(frozen=True, slots=True)
class SchedulerEvidenceRecord:
    """Immutable evidence for scheduler degraded/failure states."""

    stage: str
    state: str = "degraded"
    error_category: str = ""
    error_source: str = ""
    message: str = ""
    context: Mapping[str, object] = field(default_factory=lambda: immutable_snapshot_mapping({}))
    queue_id: str = ""
    job_id: str = ""
    worker_id: str = ""
    path: str = ""
    retry_state_affected: bool = False
    timeout_state_affected: bool = False
    final_json_must_record: bool = True
    checkpoint_must_record: bool = True
    replay_must_record: bool = True
    fatal: bool = False

    def __post_init__(self) -> None:
        field_issues: dict[str, object] = {}
        stage, issue = scheduler_text_field(self.stage, field_name="stage", default_text="scheduler")
        merge_field_issue(field_issues, issue)
        state, issue = scheduler_text_field(self.state, field_name="state", default_text="degraded")
        merge_field_issue(field_issues, issue)
        error_category, issue = scheduler_text_field(self.error_category, field_name="error_category", default_text="")
        merge_field_issue(field_issues, issue)
        error_source, issue = scheduler_text_field(self.error_source, field_name="error_source", default_text="")
        merge_field_issue(field_issues, issue)
        message, issue = scheduler_text_field(self.message, field_name="message", default_text="")
        merge_field_issue(field_issues, issue)
        queue_id, issue = scheduler_text_field(self.queue_id, field_name="queue_id", default_text="")
        merge_field_issue(field_issues, issue)
        job_id, issue = scheduler_text_field(self.job_id, field_name="job_id", default_text="")
        merge_field_issue(field_issues, issue)
        worker_id, issue = scheduler_text_field(self.worker_id, field_name="worker_id", default_text="")
        merge_field_issue(field_issues, issue)
        path, issue = scheduler_text_field(self.path, field_name="path", default_text="")
        merge_field_issue(field_issues, issue)

        retry_state_affected, issue = scheduler_bool_field(self.retry_state_affected, field_name="retry_state_affected", default=False)
        merge_field_issue(field_issues, issue)
        timeout_state_affected, issue = scheduler_bool_field(self.timeout_state_affected, field_name="timeout_state_affected", default=False)
        merge_field_issue(field_issues, issue)
        final_json_must_record, issue = scheduler_bool_field(self.final_json_must_record, field_name="final_json_must_record", default=True)
        merge_field_issue(field_issues, issue)
        checkpoint_must_record, issue = scheduler_bool_field(self.checkpoint_must_record, field_name="checkpoint_must_record", default=True)
        merge_field_issue(field_issues, issue)
        replay_must_record, issue = scheduler_bool_field(self.replay_must_record, field_name="replay_must_record", default=True)
        merge_field_issue(field_issues, issue)
        fatal, issue = scheduler_bool_field(self.fatal, field_name="fatal", default=False)
        merge_field_issue(field_issues, issue)

        object.__setattr__(self, "stage", stage)
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "error_category", error_category)
        object.__setattr__(self, "error_source", error_source)
        object.__setattr__(self, "message", message)
        object.__setattr__(self, "context", immutable_snapshot_mapping(scheduler_context_with_issues(self.context, field_issues), field_name="context"))
        object.__setattr__(self, "queue_id", queue_id)
        object.__setattr__(self, "job_id", job_id)
        object.__setattr__(self, "worker_id", worker_id)
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "retry_state_affected", retry_state_affected)
        object.__setattr__(self, "timeout_state_affected", timeout_state_affected)
        object.__setattr__(self, "final_json_must_record", final_json_must_record)
        object.__setattr__(self, "checkpoint_must_record", checkpoint_must_record)
        object.__setattr__(self, "replay_must_record", replay_must_record)
        object.__setattr__(self, "fatal", fatal)

    def as_dict(self) -> dict[str, object]:
        return {
            "stage": self.stage,
            "state": self.state,
            "error_category": self.error_category,
            "error_source": self.error_source,
            "message": self.message,
            "context": materialize_scheduler_mapping(self.context),
            "queue_id": self.queue_id,
            "job_id": self.job_id,
            "worker_id": self.worker_id,
            "path": self.path,
            "retry_state_affected": self.retry_state_affected,
            "timeout_state_affected": self.timeout_state_affected,
            "final_json_must_record": self.final_json_must_record,
            "checkpoint_must_record": self.checkpoint_must_record,
            "replay_must_record": self.replay_must_record,
            "fatal": self.fatal,
        }


    @classmethod
    def from_mapping(cls, value: object) -> "SchedulerEvidenceRecord":
        if scheduler_mapping_items(value) is None:
            return cls(
                stage="scheduler_evidence_mapping",
                state="failed",
                error_category="scheduler_evidence_mapping_rejected",
                error_source="scheduler.contracts.evidence_record",
                message="scheduler evidence mapping could not be read without caller hooks",
                context={
                    "unsupported_scheduler_evidence_mapping": unsupported_scheduler_value_evidence(
                        value,
                        field_name="scheduler_evidence_mapping",
                    )
                },
                fatal=True,
            )
        replay_required = scheduler_mapping_value(
            value,
            "replay_must_record",
            default=scheduler_mapping_value(value, "replay_must_reproduce", default=True),
        )
        return cls(
            stage=scheduler_mapping_value(value, "stage", default="scheduler"),
            state=scheduler_mapping_value(value, "state", default="degraded"),
            error_category=scheduler_mapping_value(value, "error_category", default=""),
            error_source=scheduler_mapping_value(value, "error_source", default=""),
            message=scheduler_mapping_value(value, "message", default=""),
            context=scheduler_mapping_value(value, "context", default={}),
            queue_id=first_scheduler_mapping_value(value, "queue_id", "queue_claim_id", "claim_id", default=""),
            job_id=first_scheduler_mapping_value(value, "job_id", "file_job_id", default=""),
            worker_id=scheduler_mapping_value(value, "worker_id", default=""),
            path=first_scheduler_mapping_value(value, "path", "input_file_path", "file", "node", default=""),
            retry_state_affected=scheduler_mapping_value(value, "retry_state_affected", default=False),
            timeout_state_affected=scheduler_mapping_value(value, "timeout_state_affected", default=False),
            final_json_must_record=scheduler_mapping_value(value, "final_json_must_record", default=True),
            checkpoint_must_record=scheduler_mapping_value(value, "checkpoint_must_record", default=True),
            replay_must_record=replay_required,
            fatal=scheduler_mapping_value(value, "fatal", default=False),
        )


__all__ = ("SchedulerEvidenceRecord",)
