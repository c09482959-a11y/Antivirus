"""Binary scanner public surface.

Canonical binary/entropy ownership lives in bounded modules.  This module keeps
the historical scanner import surface as direct imports only; it intentionally
contains no scanner logic, alternate implementation, or duplicate parser path.
"""

from __future__ import annotations

from Virus_Scan.scanners.binary_behavior import (
    call_detector,
    detect_attack_chain,
    detect_env_var_abuse,
    detect_evasion_signals,
    detect_ransomware_file_rename_heuristic,
    detect_staged_execution,
    engine_flow_contract_report,
)
from Virus_Scan.scanners.binary_failover import (
    should_binary_failover,
)
from Virus_Scan.scanners.binary_filetype import (
    engine_extension_key,
    filetype_validation_context,
    get_engine_filetype_info,
    get_global_filetype_info,
    update_filetype,
)
from Virus_Scan.scanners.binary_pe import (
    extract_dotnet_metadata,
    global_raw_pure_pe_header,
    is_dotnet_pe,
    scan_pure_python_pe_file,
)

__all__ = (
    "call_detector",
    "detect_attack_chain",
    "detect_env_var_abuse",
    "detect_evasion_signals",
    "detect_ransomware_file_rename_heuristic",
    "detect_staged_execution",
    "engine_extension_key",
    "engine_flow_contract_report",
    "extract_dotnet_metadata",
    "filetype_validation_context",
    "get_engine_filetype_info",
    "get_global_filetype_info",
    "global_raw_pure_pe_header",
    "is_dotnet_pe",
    "scan_pure_python_pe_file",
    "should_binary_failover",
    "update_filetype",
)
