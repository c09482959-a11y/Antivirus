"""No-hook raw queue publication boundary helpers."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_mapping_items,
    no_hook_text,
)
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items


def raw_publish_field_name(field: object) -> str:
    return str.__str__(field) if type(field) is str and field else "field"


def raw_publish_reason(field: object, suffix: str) -> str:
    return "raw_publish_" + raw_publish_field_name(field) + suffix


def raw_publish_pending_name(fid: str, seq: int, attempt: int, collector: str) -> str:
    return (
        "raw_"
        + str.__str__(fid)
        + "_"
        + int.__format__(seq, "06d")
        + "_a"
        + int.__format__(attempt, "02d")
        + "_"
        + str.__str__(collector)
        + ".json"
    )


def raw_publish_collector_name(value: object) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="raw_publish_collector_missing",
        unsupported_reason="raw_publish_collector_rejected",
    )
    if reason:
        text = "raw"
    collector = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in text)[:48]
    return collector or "raw"


def raw_publish_job_snapshot(raw_job: object) -> tuple[dict[str, object] | None, str]:
    items = no_hook_mapping_items(raw_job)
    if items is None:
        return None, "raw_publish_job_mapping_rejected"
    return scheduler_str_key_mapping_from_items(items), ""


def raw_publish_text(value: object, *, missing_reason: str, unsupported_reason: str) -> tuple[str, str]:
    return no_hook_text(value, missing_reason=missing_reason, unsupported_reason=unsupported_reason)


def raw_publish_file_text(job: Mapping[str, object]) -> tuple[str, str]:
    return raw_publish_text(
        job.get("file"),
        missing_reason="raw_publish_file_missing",
        unsupported_reason="raw_publish_file_rejected",
    )


def raw_publish_generated_file_id(value: object) -> tuple[str, str]:
    return raw_publish_text(
        value,
        missing_reason="raw_publish_generated_file_id_missing",
        unsupported_reason="raw_publish_generated_file_id_rejected",
    )


def raw_publish_existing_file_id(job: Mapping[str, object]) -> tuple[str, str]:
    return raw_publish_text(
        job.get("file_id"),
        missing_reason="raw_publish_file_id_missing",
        unsupported_reason="raw_publish_file_id_rejected",
    )


def raw_publish_sequence(job: Mapping[str, object]) -> tuple[int, str]:
    return no_hook_exact_nonnegative_int(
        job.get("seq"),
        default=0,
        reason="raw_publish_seq_parse_failed",
        non_finite_reason="raw_publish_seq_non_finite",
    )


def raw_publish_live_hard_cap(value: object) -> tuple[int, str]:
    return no_hook_exact_nonnegative_int(
        value,
        default=900,
        reason="raw_publish_live_cap_rejected",
        non_finite_reason="raw_publish_live_cap_non_finite",
    )


__all__ = (
    "raw_publish_collector_name",
    "raw_publish_existing_file_id",
    "raw_publish_field_name",
    "raw_publish_file_text",
    "raw_publish_generated_file_id",
    "raw_publish_job_snapshot",
    "raw_publish_live_hard_cap",
    "raw_publish_pending_name",
    "raw_publish_reason",
    "raw_publish_sequence",
)
