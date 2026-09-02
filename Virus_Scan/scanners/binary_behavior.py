"""Binary scanner behavioral public aggregation surface.

The canonical behavior predicates and detector orchestration are kept
in bounded modules; this file only re-exports those owned implementations.
"""

from __future__ import annotations

from Virus_Scan.scanners.binary_behavior_predicates import (
    _has_archive_dropper_behavior,
    _has_command_exec_behavior,
    _has_c2_behavior,
    _ordered_contains_subsequence,
    _binary_delayed_execution_score,
    _xor_blob_signal,
)
from Virus_Scan.scanners.binary_behavior_detectors import (
    call_detector,
    detect_attack_chain,
    detect_env_var_abuse,
    detect_evasion_signals,
    detect_ransomware_file_rename_heuristic,
    detect_staged_execution,
    engine_flow_contract_report,
)

__all__ = (
    "_binary_delayed_execution_score",
    "_has_archive_dropper_behavior",
    "_has_c2_behavior",
    "_has_command_exec_behavior",
    "_ordered_contains_subsequence",
    "_xor_blob_signal",
    "call_detector",
    "detect_attack_chain",
    "detect_env_var_abuse",
    "detect_evasion_signals",
    "detect_ransomware_file_rename_heuristic",
    "detect_staged_execution",
    "engine_flow_contract_report",
)
