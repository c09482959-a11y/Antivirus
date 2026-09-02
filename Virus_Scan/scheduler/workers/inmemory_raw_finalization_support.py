"""No-hook support helpers for in-memory raw finalization."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_value
from typing import TypedDict

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_sequence_items
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_text
from Virus_Scan.scheduler.queue.raw_accumulator_yara_evidence import append_accumulator_yara_evidence


class InMemoryRawSummary(TypedDict):
    tags: list[str]
    yara_hits: list[object]
    yara_evidence: object
    strings_blob: str
    errors: list[str]
    suspicious: bool



def safe_raw_text(value: object, *, replacement_text: str = "") -> str:
    text, reason = scheduler_text(value, replacement_text=replacement_text)
    if reason == "":
        return text
    return replacement_text


def raw_tag_values(value: object) -> list[str]:
    out: list[str] = []
    for item in no_hook_sequence_items(value):
        text = safe_raw_text(item)
        if text:
            out.append(text)
    return out


def raw_error_values(value: object) -> list[str]:
    out: list[str] = []
    for item in no_hook_sequence_items(value):
        text = safe_raw_text(item, replacement_text="raw_error_rejected")
        if text:
            out.append(text[:500])
    return out


def result_error_present(result: object) -> bool:
    if scheduler_mapping_value(result, "error") is not None:
        return True
    errors = no_hook_sequence_items(scheduler_mapping_value(result, "errors", ()))
    return len(errors) > 0


def summarize_inmemory_raw_results(raw_results: list[dict[str, object]]) -> InMemoryRawSummary:
    tags: list[str] = []
    yara_hits: list[object] = []
    yara_evidence_owner: dict[str, object] = {"yara_evidence": None, "errors": [], "degraded": False}
    strings_parts: list[str] = []
    errors: list[str] = []
    suspicious = False
    for result in no_hook_sequence_items(raw_results):
        if no_hook_mapping_items(result) is None:
            continue
        tags.extend(raw_tag_values(scheduler_mapping_value(result, "tags", ())))
        yara_hits.extend(no_hook_sequence_items(scheduler_mapping_value(result, "yara_hits", ())))
        append_accumulator_yara_evidence(yara_evidence_owner, result)
        strings_blob = safe_raw_text(scheduler_mapping_value(result, "strings_blob"))
        if strings_blob:
            strings_parts.append(strings_blob[:65536])
        errors.extend(raw_error_values(scheduler_mapping_value(result, "errors", ())))
        error_text = safe_raw_text(scheduler_mapping_value(result, "error"), replacement_text="")
        if error_text:
            errors.append(error_text[:500])
        suspicious_value, suspicious_reason = scheduler_bool(
            scheduler_mapping_value(result, "suspicious"),
            default=False,
            reason="raw_result_suspicious_rejected",
        )
        if suspicious_reason == "" and suspicious_value:
            suspicious = True
    return {
        "tags": tags,
        "yara_hits": yara_hits,
        "yara_evidence": dict.get(yara_evidence_owner, "yara_evidence"),
        "strings_blob": "\n".join(strings_parts)[:262144],
        "errors": errors,
        "suspicious": suspicious,
    }


__all__ = (
    "InMemoryRawSummary",
    "raw_error_values",
    "raw_tag_values",
    "result_error_present",
    "safe_raw_text",
    "summarize_inmemory_raw_results",
)
