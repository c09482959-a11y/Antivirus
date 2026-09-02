"""Immutable queue integrity records and summaries."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, immutable_tuple, materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.no_hook_attrs import scheduler_exact_attr
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_filesystem_path, scheduler_int, scheduler_text
_QUEUE_IDENTITY_MISSING_STATE = "queue identity record missing state"
_QUEUE_IDENTITY_MISSING_PATH = "queue identity record missing path"
_QUEUE_IDENTITY_MISSING_NAME = "queue identity record missing name"
_QUEUE_IDENTITY_JOB_NOT_MAPPING = "queue identity record job must be a mapping"
_QUEUE_INTEGRITY_SUMMARY_MAPPING_REJECTED = "queue integrity summary mapping rejected"


_QUEUE_INTEGRITY_REJECTION_REASONS = (
    ("duplicates", "queue_integrity_duplicates_rejected"),
    ("quarantined", "queue_integrity_quarantined_rejected"),
    ("invalid", "queue_integrity_invalid_rejected"),
)
@dataclass(frozen=True, slots=True)
class QueueIdentityRecord:
    """Immutable queue-identity observation used during integrity validation."""
    state: str
    path: Path
    name: str
    job: Mapping[str, object]
    def __post_init__(self) -> None:
        state, state_reason = scheduler_text(self.state, unsupported_reason="queue_identity_state_rejected")
        path, path_reason = scheduler_filesystem_path(self.path)
        name, name_reason = scheduler_text(self.name, unsupported_reason="queue_identity_name_rejected")
        job_items = no_hook_mapping_items(self.job)
        if state_reason or not state:
            raise ValueError(_QUEUE_IDENTITY_MISSING_STATE)
        if path_reason or not path:
            raise ValueError(_QUEUE_IDENTITY_MISSING_PATH)
        if name_reason or not name:
            raise ValueError(_QUEUE_IDENTITY_MISSING_NAME)
        if job_items is None:
            raise ValueError(_QUEUE_IDENTITY_JOB_NOT_MAPPING)
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "path", Path(path))
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "job", immutable_mapping(dict(job_items)))
    @classmethod
    def from_observation(cls, *, state: object, path: object, name: object, job: object) -> "QueueIdentityRecord":
        state_text, state_reason = scheduler_text(state, unsupported_reason="queue_identity_state_rejected")
        path_value, path_reason = scheduler_filesystem_path(path)
        name_text, name_reason = scheduler_text(name, unsupported_reason="queue_identity_name_rejected")
        job_items = no_hook_mapping_items(job)
        if state_reason or not state_text:
            raise ValueError(_QUEUE_IDENTITY_MISSING_STATE)
        if path_reason or not path_value:
            raise ValueError(_QUEUE_IDENTITY_MISSING_PATH)
        if name_reason or not name_text:
            raise ValueError(_QUEUE_IDENTITY_MISSING_NAME)
        if job_items is None:
            raise ValueError(_QUEUE_IDENTITY_JOB_NOT_MAPPING)
        normalized_path = Path(path_value)
        normalized_job: dict[str, object] = dict(job_items)
        return cls(state=state_text, path=normalized_path, name=name_text, job=normalized_job)
    def as_dict(self) -> dict[str, object]:
        return {"state": self.state, "path": self.path, "name": self.name, "job": materialize_scheduler_mapping(self.job)}
@dataclass(frozen=True, slots=True)
class QueueIntegritySummary:
    """Immutable queue-integrity result snapshot."""
    duplicates: int = 0
    quarantined: int = 0
    invalid: int = 0
    expected_files: int | None = None
    expected_files_evidence: tuple[object, ...] = ()
    integrity_complete: bool = True
    integrity_error: str = ""
    queue_identity_collection_failed: bool = False
    queue_identity_collection_evidence: tuple[object, ...] = ()
    def __post_init__(self) -> None:
        normalized_counts: dict[str, int] = {}
        reasons: list[str] = []
        for field_name in ("duplicates", "quarantined", "invalid"):
            parsed, reason = scheduler_int(
                scheduler_exact_attr(self, field_name, owner_type=QueueIntegritySummary),
                minimum=0,
                reason=next(
                    (reason for candidate, reason in _QUEUE_INTEGRITY_REJECTION_REASONS if field_name == candidate),
                    "queue_integrity_field_rejected",
                ),
            )
            normalized_counts[field_name] = parsed
            if reason:
                reasons.append(reason)
        if self.expected_files is None:
            expected_files = None
        else:
            expected_files, expected_reason = scheduler_int(
                self.expected_files,
                minimum=0,
                reason="queue_integrity_expected_files_rejected",
            )
            if expected_reason:
                reasons.append(expected_reason)
        if type(self.expected_files_evidence) not in {list, tuple}:
            reasons.append("queue_integrity_expected_files_evidence_rejected")
        integrity_complete, complete_reason = scheduler_bool(
            self.integrity_complete,
            reason="queue_integrity_complete_rejected",
        )
        collection_failed, failed_reason = scheduler_bool(
            self.queue_identity_collection_failed,
            reason="queue_integrity_collection_failed_rejected",
        )
        integrity_error, error_reason = scheduler_text(self.integrity_error, unsupported_reason="queue_integrity_error_rejected")
        reasons.extend(reason for reason in (complete_reason, failed_reason, error_reason) if reason)
        if type(self.queue_identity_collection_evidence) not in {list, tuple}:
            reasons.append("queue_integrity_collection_evidence_rejected")
        if reasons:
            raise ValueError(",".join(reasons))
        object.__setattr__(self, "duplicates", normalized_counts["duplicates"])
        object.__setattr__(self, "quarantined", normalized_counts["quarantined"])
        object.__setattr__(self, "invalid", normalized_counts["invalid"])
        object.__setattr__(self, "expected_files", expected_files)
        object.__setattr__(self, "expected_files_evidence", immutable_tuple(self.expected_files_evidence))
        object.__setattr__(self, "integrity_complete", integrity_complete)
        object.__setattr__(self, "integrity_error", integrity_error)
        object.__setattr__(self, "queue_identity_collection_failed", collection_failed)
        object.__setattr__(self, "queue_identity_collection_evidence", immutable_tuple(self.queue_identity_collection_evidence))
    def as_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "duplicates": self.duplicates,
            "quarantined": self.quarantined,
            "invalid": self.invalid,
            "expected_files": self.expected_files,
            "integrity_complete": self.integrity_complete,
        }
        if self.expected_files_evidence:
            out["expected_files_evidence"] = materialize_scheduler_mapping(self.expected_files_evidence)
        if self.integrity_error:
            out["integrity_error"] = self.integrity_error
        if self.queue_identity_collection_failed:
            out["queue_identity_collection_failed"] = True
            out["queue_identity_collection_evidence"] = materialize_scheduler_mapping(self.queue_identity_collection_evidence)
        return out
    def assert_forensic_complete(self, *, context: str = "queue_integrity") -> None:
        if not self.integrity_complete:
            context_text, context_reason = scheduler_text(
                context,
                unsupported_reason="queue_integrity_context_rejected",
            )
            if context_reason or not context_text:
                context_text = "queue_integrity"
            integrity_error = self.integrity_error or "unknown"
            raise RuntimeError(
                context_text
                + ": queue integrity did not complete: "
                + integrity_error
            )
        if self.duplicates or self.invalid:
            context_text, context_reason = scheduler_text(
                context,
                unsupported_reason="queue_integrity_context_rejected",
            )
            if context_reason or not context_text:
                context_text = "queue_integrity"
            raise RuntimeError(
                context_text
                + ": queue integrity violations remain: duplicates="
                + int.__str__(self.duplicates)
                + " invalid="
                + int.__str__(self.invalid)
            )
def _summary_from_dict(summary: Mapping[str, object]) -> QueueIntegritySummary:
    summary_items = no_hook_mapping_items(summary)
    if summary_items is None:
        raise ValueError(_QUEUE_INTEGRITY_SUMMARY_MAPPING_REJECTED)
    snapshot = dict(summary_items)
    return QueueIntegritySummary(
        duplicates=dict.get(snapshot, "duplicates", 0),
        quarantined=dict.get(snapshot, "quarantined", 0),
        invalid=dict.get(snapshot, "invalid", 0),
        expected_files=dict.get(snapshot, "expected_files"),
        expected_files_evidence=dict.get(snapshot, "expected_files_evidence", ()),
        integrity_complete=dict.get(snapshot, "integrity_complete", False),
        integrity_error=dict.get(snapshot, "integrity_error", ""),
        queue_identity_collection_failed=dict.get(snapshot, "queue_identity_collection_failed", False),
        queue_identity_collection_evidence=dict.get(snapshot, "queue_identity_collection_evidence", ()),
    )
def validate_queue_integrity_summary(summary: Mapping[str, object], *, context: str = "queue_integrity") -> bool:
    _summary_from_dict(summary).assert_forensic_complete(context=context)
    return True
