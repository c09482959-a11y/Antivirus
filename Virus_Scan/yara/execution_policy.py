"""Canonical scan-mode selection for the existing YARA runtime owner."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.runtime.config_state import get_deep_scan_mode
from Virus_Scan.runtime.yara_rules_state import (
    YaraLightSnapshot,
    YaraRulesSnapshot,
    YaraRulesState,
    yara_rules_state,
)

YARA_CORE_PACKAGE = "core"
YARA_EXTENDED_PACKAGE = "extended"


def yara_package_for_scan_mode(scan_mode: object = None) -> str:
    """Return the only rule package authorized for the current scan mode."""
    value = get_deep_scan_mode("auto") if scan_mode is None else scan_mode
    text, reason = no_hook_text(
        value,
        missing_reason="yara_scan_mode_missing",
        unsupported_reason="yara_scan_mode_rejected",
    )
    if reason:
        raise ValueError(reason)
    normalized = text.strip().lower()
    if normalized == "":
        normalized = "auto"
    return YARA_CORE_PACKAGE if normalized == "fast" else YARA_EXTENDED_PACKAGE


def yara_light_selected(scan_mode: object = None) -> bool:
    return yara_package_for_scan_mode(scan_mode) == YARA_CORE_PACKAGE


def selected_yara_snapshot(
    state: object = None,
    *,
    scan_mode: object = None,
) -> YaraLightSnapshot | YaraRulesSnapshot:
    """Read the authorized snapshot from the single canonical runtime owner."""
    owner = yara_rules_state() if state is None else state
    if type(owner) is not YaraRulesState:
        raise TypeError("yara_rules_state_owner_invalid")
    if yara_light_selected(scan_mode):
        return owner.light_snapshot()
    return owner.primary_snapshot()


def selected_yara_snapshot_ready(snapshot: object) -> bool:
    if type(snapshot) is YaraLightSnapshot:
        return snapshot.ok is True and snapshot.rules is not None
    if type(snapshot) is YaraRulesSnapshot:
        return snapshot.rules is not None
    raise TypeError("yara_selected_snapshot_invalid")


__all__ = (
    "YARA_CORE_PACKAGE",
    "YARA_EXTENDED_PACKAGE",
    "selected_yara_snapshot",
    "selected_yara_snapshot_ready",
    "yara_light_selected",
    "yara_package_for_scan_mode",
)
