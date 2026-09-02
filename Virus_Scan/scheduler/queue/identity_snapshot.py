"""Immutable exact-primitive queue identity inputs."""
from __future__ import annotations

from dataclasses import dataclass


from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text

def _identity_text(
    value: object,
    *,
    field: str,
    default: str,
    rejections: list[str],
) -> str:
    reasons = {
        "queue_file_id": ("process_queue_identity_queue_file_id_missing", "process_queue_identity_queue_file_id_rejected"),
        "job_type": ("process_queue_identity_job_type_missing", "process_queue_identity_job_type_rejected"),
        "file": ("process_queue_identity_file_missing", "process_queue_identity_file_rejected"),
        "file_id": ("process_queue_identity_file_id_missing", "process_queue_identity_file_id_rejected"),
        "collector": ("process_queue_identity_collector_missing", "process_queue_identity_collector_rejected"),
        "seq": ("process_queue_identity_seq_missing", "process_queue_identity_seq_rejected"),
        "attempt": ("process_queue_identity_attempt_missing", "process_queue_identity_attempt_rejected"),
        "source_name": ("process_queue_identity_source_name_missing", "process_queue_identity_source_name_rejected"),
    }
    missing_reason, unsupported_reason = dict.get(
        reasons,
        field,
        ("process_queue_identity_unknown_missing", "process_queue_identity_unknown_rejected"),
    )
    text, reason = no_hook_text(
        value,
        missing_reason=missing_reason,
        unsupported_reason=unsupported_reason,
    )
    if reason:
        if value is not None:
            rejections.append(reason)
        return default
    return text


@dataclass(frozen=True, slots=True)
class QueueJobIdentitySnapshot:
    """Exact values used by the canonical durable identity derivation."""

    queue_file_id: str
    job_type: str
    file: str
    file_id: str
    collector: str
    seq: str
    attempt: str
    source_name: str
    rejections: tuple[str, ...] = ()

    @classmethod
    def from_job(cls, job: object, source_name: object = None) -> "QueueJobIdentitySnapshot":
        items = no_hook_mapping_items(job)
        data = dict(items) if items is not None else {}
        rejections: list[str] = []
        seq_value = dict.get(data, "seq")
        if seq_value is None:
            seq_value = dict.get(data, "index")
        file_value = dict.get(data, "file")
        file_id_value = dict.get(data, "file_id")
        if file_id_value is None:
            file_id_value = dict.get(data, "raw_file_id")
        if file_id_value is None:
            file_id_value = file_value
        field_values = (
            ("queue_file_id", dict.get(data, "queue_file_id"), ""),
            ("job_type", dict.get(data, "job_type"), "file"),
            ("file", file_value, ""),
            ("file_id", file_id_value, ""),
            ("collector", dict.get(data, "collector"), ""),
            ("seq", seq_value, ""),
            ("attempt", dict.get(data, "attempt"), "0"),
            ("source_name", source_name, "unknown"),
        )
        parsed: dict[str, str] = {}
        for field, value, default in field_values:
            parsed[field] = _identity_text(
                value,
                field=field,
                default=default,
                rejections=rejections,
            )
        return cls(**parsed, rejections=tuple(rejections))


__all__ = ("QueueJobIdentitySnapshot",)
