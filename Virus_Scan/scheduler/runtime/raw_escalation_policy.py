"""Scheduler-owned in-memory raw/deep escalation policy."""
from __future__ import annotations

from typing import Iterable, TYPE_CHECKING

from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.detection.api.public_contracts import contextual_dangerous_anchor_hits
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.api import get_deep_scan_mode
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_sequence_items,
)
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
    scheduler_text,
)

if TYPE_CHECKING:
    from pathlib import Path

_ESCALATION_TAGS = frozenset({
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
    "packed_or_obfuscated",
    "very_high_entropy",
    "high_entropy_section",
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

_HIGH_RISK_EXTENSIONS = frozenset({".exe", ".scr", ".sys", ".ps1", ".vbs", ".jse", ".bat", ".cmd"})
_HIGH_RISK_EXECUTION_TAGS = frozenset({"script_execution", "process_exec", "encoded_powershell", "powershell_exec", "cmd_exec"})
RAW_ESCALATION_REQUIRED = True
RAW_ESCALATION_NOT_REQUIRED = False


def _record_raw_escalation_failure(where: str, exc: BaseException) -> None:
    try:
        record_suppressed_failure(where, exc, domain="scheduler")
    except RECOVERABLE_RUNTIME_ERRORS as report_exc:
        _ = report_exc


def _raw_evidence_present(value: object) -> tuple[bool, str]:
    if value is None or value is False:
        return RAW_ESCALATION_NOT_REQUIRED, ""
    if type(value) is bool:
        return value, ""
    if type(value) in {int, float}:
        return value != 0, ""
    if type(value) is str:
        return str.__len__(value) > 0, ""
    if type(value) in {tuple, list, set, frozenset, dict}:
        return len(value) > 0, ""
    return RAW_ESCALATION_REQUIRED, "scheduler_raw_prefilter_evidence_rejected"


def should_escalate_after_inmemory_triage(
    path: str | Path,
    tags: Iterable[str] | None,
    suspicious: bool,
    prefilter_info: dict[str, object] | None,
    curr_stage: str | None,
) -> bool:
    """Decide whether in-memory file scanning must escalate to raw/deep collection."""
    _ = curr_stage
    if tags is None:
        tagset = frozenset()
    elif type(tags) not in {tuple, list, set, frozenset}:
        _record_raw_escalation_failure(
            "scheduler_raw_escalation_tags_rejected",
            ValueError("scheduler_raw_escalation_tags_rejected"),
        )
        return RAW_ESCALATION_REQUIRED
    else:
        out: list[str] = []
        for item in no_hook_sequence_items(tags):
            text, tag_reason = scheduler_text(
                item,
                unsupported_reason="scheduler_raw_escalation_tag_rejected",
            )
            if tag_reason:
                _record_raw_escalation_failure(
                    "scheduler_raw_escalation_tags_rejected",
                    ValueError(tag_reason),
                )
                return RAW_ESCALATION_REQUIRED
            normalized = text.strip().lower()
            if normalized:
                out.append(normalized)
        tagset = frozenset(out)

    try:
        extension = get_scan_extension(path)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        _record_raw_escalation_failure("scheduler_raw_escalation_extension_failed", exc)
        return RAW_ESCALATION_REQUIRED

    mode, mode_reason = scheduler_text(
        get_deep_scan_mode("auto"),
        replacement_text="auto",
        unsupported_reason="scheduler_deep_scan_mode_rejected",
    )
    if mode_reason:
        _record_raw_escalation_failure("scheduler_deep_scan_mode_rejected", ValueError(mode_reason))
        return RAW_ESCALATION_REQUIRED
    if mode.lower() in {"thorough", "deep", "exhaustive"}:
        return RAW_ESCALATION_REQUIRED

    suspicious_flag, suspicious_reason = scheduler_bool(
        suspicious,
        reason="scheduler_raw_suspicious_flag_rejected",
    )
    if suspicious_reason:
        _record_raw_escalation_failure(
            "scheduler_raw_suspicious_flag_rejected",
            ValueError(suspicious_reason),
        )
        return RAW_ESCALATION_REQUIRED
    if suspicious_flag:
        return RAW_ESCALATION_REQUIRED

    if prefilter_info is not None:
        items = no_hook_mapping_items(prefilter_info)
        if items is None:
            _record_raw_escalation_failure(
                "scheduler_raw_prefilter_mapping_rejected",
                ValueError("scheduler_raw_prefilter_mapping_rejected"),
            )
            return RAW_ESCALATION_REQUIRED
        prefilter_snapshot = dict(items)
        for key in ("hits",):
            present, prefilter_reason = _raw_evidence_present(dict.get(prefilter_snapshot, key))
            if prefilter_reason:
                _record_raw_escalation_failure(
                    "scheduler_raw_prefilter_evidence_rejected",
                    ValueError(prefilter_reason),
                )
                return RAW_ESCALATION_REQUIRED
            if present:
                return RAW_ESCALATION_REQUIRED

    if tagset & _ESCALATION_TAGS:
        return RAW_ESCALATION_REQUIRED

    try:
        anchor_result = contextual_dangerous_anchor_hits(set(tagset))
        anchor_hit, anchor_reason = _raw_evidence_present(anchor_result)
        if anchor_reason:
            _record_raw_escalation_failure("scheduler_raw_anchor_result_rejected", ValueError(anchor_reason))
            return RAW_ESCALATION_REQUIRED
        if anchor_hit:
            return RAW_ESCALATION_REQUIRED
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        _record_raw_escalation_failure("scheduler_raw_escalation_anchor_check_failed", exc)

    return extension in _HIGH_RISK_EXTENSIONS and len(tagset & _HIGH_RISK_EXECUTION_TAGS) > 0


__all__ = ("should_escalate_after_inmemory_triage",)
