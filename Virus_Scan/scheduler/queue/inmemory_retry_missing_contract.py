"""Immutable evidence contracts for unavailable retry job records."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.scheduler.internal.no_hook_attrs import scheduler_exact_attr
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
    scheduler_int,
    scheduler_text,
)

_RECORD_FLAGS = (
    "final_json_must_record",
    "checkpoint_must_record",
    "replay_must_reproduce",
)

_RETRY_REJECTION_REASONS = (
    ("job_id", "inmemory_retry_job_id_rejected"),
    ("generation", "inmemory_retry_generation_rejected"),
    ("reason", "inmemory_retry_reason_rejected"),
    ("error_category", "inmemory_retry_error_category_rejected"),
    ("error_source", "inmemory_retry_error_source_rejected"),
    ("detail", "inmemory_retry_detail_rejected"),
    ("final_json_must_record", "inmemory_retry_final_json_must_record_rejected"),
    ("checkpoint_must_record", "inmemory_retry_checkpoint_must_record_rejected"),
    ("replay_must_reproduce", "inmemory_retry_replay_must_reproduce_rejected"),
)

def _retry_rejection_reason(field_name: object) -> str:
    if type(field_name) is str:
        field_text = str.__str__(field_name)
        for candidate, reason in _RETRY_REJECTION_REASONS:
            if field_text == candidate:
                return reason
    return "inmemory_retry_field_rejected"


def _retry_int(value: object, *, field_name: str) -> int:
    parsed, reason = scheduler_int(
        value,
        minimum=0,
        reason=_retry_rejection_reason(field_name),
    )
    if reason:
        raise ValueError(reason)
    return parsed



def _normalize(instance: object, text_fields: tuple[str, ...]) -> None:
    for field_name in ("job_id", "generation"):
        object.__setattr__(
            instance,
            field_name,
            _retry_int(
                scheduler_exact_attr(instance, field_name, owner_type=type(instance)),
                field_name=field_name,
            ),
        )
    for field_name in text_fields:
        text, text_reason = scheduler_text(
            scheduler_exact_attr(instance, field_name, owner_type=type(instance)),
            unsupported_reason=_retry_rejection_reason(field_name),
        )
        if text_reason:
            raise ValueError(text_reason)
        object.__setattr__(instance, field_name, text)
    for field_name in _RECORD_FLAGS:
        flag, reason = scheduler_bool(
            scheduler_exact_attr(instance, field_name, owner_type=type(instance)),
            reason=_retry_rejection_reason(field_name),
        )
        if reason:
            raise ValueError(reason)
        object.__setattr__(instance, field_name, flag)


def _record(instance: object, *, stage: str, fixed: Mapping[str, object]) -> object:
    record = {
        "stage": stage,
        "job_id": instance.job_id,
        "generation": instance.generation,
        "reason": instance.reason,
        "detail": instance.detail[:1000],
        **fixed,
    }
    for field_name in _RECORD_FLAGS:
        record[field_name] = scheduler_exact_attr(instance, field_name, owner_type=type(instance))
    return MappingProxyType(record)


@dataclass(frozen=True, slots=True)
class InMemoryRetryMissingRecordEvidence:
    job_id: int
    reason: str
    error_category: str
    error_source: str
    detail: str
    generation: int = 0
    final_json_must_record: bool = True
    checkpoint_must_record: bool = True
    replay_must_reproduce: bool = True

    def __post_init__(self) -> None:
        _normalize(
            self,
            ("reason", "error_category", "error_source", "detail"),
        )

    def as_record(self) -> Mapping[str, object]:
        return _record(
            self,
            stage="inmemory_retry_missing_record",
            fixed={
                "error_category": self.error_category,
                "error_source": self.error_source,
                "queue_failure": True,
                "retry_failure": True,
            },
        )


@dataclass(frozen=True, slots=True)
class InMemoryRetryDuplicatePendingEvidence:
    job_id: int
    generation: int
    reason: str
    detail: str
    final_json_must_record: bool = True
    checkpoint_must_record: bool = True
    replay_must_reproduce: bool = True

    def __post_init__(self) -> None:
        _normalize(self, ("reason", "detail"))

    def as_record(self) -> Mapping[str, object]:
        return _record(
            self,
            stage="inmemory_retry_duplicate_pending",
            fixed={
                "error_category": "DuplicateRetryPending",
                "error_source": "inmemory_retry_recovery.retry_already_pending",
                "queue_failure": True,
                "retry_failure": True,
            },
        )


@dataclass(frozen=True, slots=True)
class InMemoryRetryTerminalAlreadyEvidence:
    job_id: int
    reason: str
    detail: str
    generation: int = 0
    final_json_must_record: bool = True
    checkpoint_must_record: bool = True
    replay_must_reproduce: bool = True

    def __post_init__(self) -> None:
        _normalize(self, ("reason", "detail"))

    def as_record(self) -> Mapping[str, object]:
        return _record(
            self,
            stage="inmemory_retry_terminal_already",
            fixed={
                "error_category": "TerminalRetryRequest",
                "error_source": "inmemory_retry_recovery.terminal",
                "queue_failure": True,
                "retry_failure": True,
            },
        )


__all__ = (
    "InMemoryRetryDuplicatePendingEvidence",
    "InMemoryRetryMissingRecordEvidence",
    "InMemoryRetryTerminalAlreadyEvidence",
    "_retry_int",
)
