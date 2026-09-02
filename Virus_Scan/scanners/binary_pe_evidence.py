"""Scanner-owned PE failure/evidence helpers."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.scanners.binary_io import binary_log_message
from Virus_Scan.scanners.binary_exception_policy import is_binary_programmer_error
from Virus_Scan.scanners.contracts import scanner_failure_evidence_tags
from Virus_Scan.utils.tagging import ordered_unique_tags


def _pe_helper_name(helper_name: str) -> str:
    text, reason = no_hook_text(
        helper_name,
        missing_reason="missing_pe_helper_name",
        unsupported_reason="unsafe_pe_helper_name_rejected",
    )
    if reason or not text:
        return "pe_helper_unsupported"
    return text.strip() or "pe_helper_unsupported"


def mark_pe_helper_error(helper_name: str, exc: BaseException) -> list[str]:
    """Record scan-affecting PE helper failure with final-JSON evidence markers."""
    if is_binary_programmer_error(exc):
        raise exc
    helper_text = _pe_helper_name(helper_name)
    binary_log_message(helper_text + " failed")
    tags = scanner_failure_evidence_tags("binary", helper_text, exc, [helper_text + "_scan_error"], state="degraded", error_category="pe_helper_failure", file_type="binary")
    evidence_markers = (
        "binary_final_json_must_record",
        "scanner_failure_evidence_recorded",
        "scanner_failure_evidence:binary:" + helper_text,
    )
    for marker in evidence_markers:
        if marker not in tags:
            tags.append(marker)
    return tags


def immutable_tag_tuple(tags: object) -> tuple[str, ...]:
    """Freeze explicit scanner evidence tags without caller-owned hooks."""
    return tuple(ordered_unique_tags(tags))


__all__ = ("mark_pe_helper_error", "immutable_tag_tuple")
