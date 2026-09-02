"""Scheduler-owned passive asset triage predicates."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from Virus_Scan.utils.tagging import normalize_tags

_TERMINAL_BLOCKING_TAGS = frozenset({
    "asset_deep_scan_escalated",
    "extension_mismatch",
    "extension_magic_type_mismatch",
    "embedded_script_marker",
    "embedded_executable_marker",
    "embedded_archive_marker",
    "asset_embedded_script_marker",
    "asset_embedded_executable_marker",
    "asset_embedded_archive_marker",
    "suspicious_media_asset",
    "scan_router_error",
    "binary_failover_scan",
    "packed_or_obfuscated",
    "high_entropy_packed",
    "very_high_entropy",
    "network_download",
    "process_exec",
    "powershell_exec",
    "cmd_exec",
    "script_execution",
    "process_injection",
    "credential_access",
})

_TERMINAL_CLEAN_TAGS = frozenset({
    "asset_fast_triage",
    "unity_container_fast_triage_clean",
    "media_asset",
    "image_fast_triage_clean",
    "font_fast_triage_clean",
    "passive_asset_fast_triage_clean",
})


@dataclass(frozen=True)
class TerminalCleanAssetTriageDecision:
    is_terminal_clean: bool
    reason: str
    normalized_tags: frozenset[str]


def is_terminal_clean_asset_triage_decision(
    tags: Iterable[str] | None,
    *, suspicious: bool = False,
) -> TerminalCleanAssetTriageDecision:
    """Return replayable passive-asset terminal-clean triage state."""
    tagset = frozenset(normalize_tags(tags or []))
    if suspicious:
        return TerminalCleanAssetTriageDecision(
            is_terminal_clean=False,
            reason="suspicious_asset_triage_blocked",
            normalized_tags=tagset,
        )
    if tagset & _TERMINAL_BLOCKING_TAGS:
        return TerminalCleanAssetTriageDecision(
            is_terminal_clean=False,
            reason="terminal_blocking_tag_present",
            normalized_tags=tagset,
        )
    return TerminalCleanAssetTriageDecision(
        is_terminal_clean=bool(tagset & _TERMINAL_CLEAN_TAGS),
        reason="terminal_clean_tag_present" if tagset & _TERMINAL_CLEAN_TAGS else "terminal_clean_tag_missing",
        normalized_tags=tagset,
    )


def is_terminal_clean_asset_triage(tags: Iterable[str] | None, *, suspicious: bool = False) -> bool:
    """Return whether passive media/Unity asset validation can terminate cleanly."""
    return is_terminal_clean_asset_triage_decision(tags, suspicious=suspicious).is_terminal_clean


__all__ = (
    "TerminalCleanAssetTriageDecision",
    "is_terminal_clean_asset_triage",
    "is_terminal_clean_asset_triage_decision",
)
