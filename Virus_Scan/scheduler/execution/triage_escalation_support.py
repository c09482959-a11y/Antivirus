"""Helper policy for scheduler post-triage escalation."""
from __future__ import annotations

from typing import Callable, Mapping, TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_sequence_items,
)
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
    scheduler_text,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

ESCALATION_TAGS = frozenset({
    "asset_deep_scan_escalated",
    "extension_magic_type_mismatch",
    "asset_extension_magic_mismatch",
    "binary_failover",
    "router_binary_failover",
    "embedded_pe_signature",
    "embedded_archive_signature",
    "possible_appended_payload",
    "asset_embedded_payload_signature",
    "yara_hit",
    "yaralight_hit",
    "pickle_deep_scan_escalated",
    "pickle_fast_protocol_hint",
    "pickle_fast_base64_protocol_hint",
    "pickle_fast_text_hint",
    "pickle_fast_exec_context",
    "pickle_source_escalation",
    "pickle_deserialization_context",
    "pickle_opcode_graph_analyzed",
    "pickle_dangerous_global",
    "pickle_reduce_opcode",
})
HIGH_RISK_EXTS = frozenset({".exe", ".scr", ".sys", ".ps1", ".vbs", ".jse", ".bat", ".cmd"})
EXECUTION_TAGS = frozenset({"script_execution", "process_exec", "encoded_powershell", "powershell_exec", "cmd_exec"})


def record_boundary_rejection(record_suppressed_failure: object, where: str, reason: str) -> None:
    record_suppressed_failure(where, ValueError(reason))


def exact_evidence_present(value: object) -> tuple[bool, str]:
    if value is None or value is False:
        return False, ""
    if type(value) is bool:
        return value, ""
    if type(value) in {int, float}:
        return value != 0, ""
    if type(value) is str:
        return str.__len__(value) > 0, ""
    if type(value) in {tuple, list, set, frozenset, dict}:
        return len(value) > 0, ""
    return True, "scheduler_prefilter_evidence_rejected"


def tag_snapshot(tags: object) -> tuple[frozenset[str], str]:
    if tags is None:
        return frozenset(), ""
    if type(tags) not in {tuple, list, set, frozenset}:
        return frozenset(), "scheduler_triage_tags_rejected"
    out: list[str] = []
    for item in no_hook_sequence_items(tags):
        text, reason = scheduler_text(
            item,
            unsupported_reason="scheduler_triage_tag_rejected",
        )
        if reason:
            return frozenset(), reason
        normalized = text.strip().lower()
        if normalized:
            out.append(normalized)
    return frozenset(out), ""


def truthy_scheduler_flag(
    *,
    value: object,
    reason: str,
    record_suppressed_failure: Callable[[str, BaseException], object],
) -> tuple[bool, bool]:
    flag, rejection = scheduler_bool(value, reason=reason)
    if rejection:
        record_boundary_rejection(record_suppressed_failure, reason, rejection)
        return False, True
    return flag, flag


def prefilter_requires_escalation(
    *,
    prefilter_info: Mapping[str, object] | None,
    record_suppressed_failure: Callable[[str, BaseException], object],
) -> bool:
    if prefilter_info is None:
        return False
    items = no_hook_mapping_items(prefilter_info)
    if items is None:
        record_boundary_rejection(
            record_suppressed_failure,
            "scheduler_prefilter_mapping_rejected",
            "scheduler_prefilter_mapping_rejected",
        )
        return True
    prefilter_snapshot = dict(items)
    for key in ("hits",):
        present, reason = exact_evidence_present(dict.get(prefilter_snapshot, key))
        if reason:
            record_boundary_rejection(
                record_suppressed_failure,
                "scheduler_prefilter_evidence_rejected",
                reason,
            )
            return True
        if present:
            return True
    return False


def anchor_requires_escalation(
    *,
    tagset: frozenset[str],
    contextual_dangerous_anchor_hits: Callable[[Iterable[object] | None], list[str]],
    record_suppressed_failure: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> bool:
    try:
        anchor_result = contextual_dangerous_anchor_hits(set(tagset))
        anchor_hit, anchor_reason = exact_evidence_present(anchor_result)
        if anchor_reason:
            record_boundary_rejection(
                record_suppressed_failure,
                "scheduler_anchor_result_rejected",
                anchor_reason,
            )
            return True
        return anchor_hit
    except recoverable_exceptions as exc:
        try:
            record_suppressed_failure("suppressed_exception", exc)
        except recoverable_exceptions as record_exc:
            _ = record_exc
    return False


__all__ = (
    "ESCALATION_TAGS",
    "EXECUTION_TAGS",
    "HIGH_RISK_EXTS",
    "anchor_requires_escalation",
    "prefilter_requires_escalation",
    "record_boundary_rejection",
    "scheduler_text",
    "tag_snapshot",
    "truthy_scheduler_flag",
)
