from __future__ import annotations

from Virus_Scan.scanners.config.loader import load_binary_policy_snapshot
from Virus_Scan.scanners.contracts import scanner_contract_lower_token

_BINARY_POLICY = load_binary_policy_snapshot()
DOTNET_EXTENSIONS = _BINARY_POLICY.dotnet_extensions
DOTNET_METADATA_MARKERS = _BINARY_POLICY.dotnet_metadata_markers
DOTNET_BEHAVIOR_MARKERS = _BINARY_POLICY.dotnet_behavior_markers
DOTNET_EXTENSION_MISMATCH_EXTENSIONS = _BINARY_POLICY.dotnet_extension_mismatch_extensions

def dotnet_metadata_present(blob: str) -> bool:
    low = scanner_contract_lower_token(blob, replacement='')
    return any(marker in low for marker in DOTNET_METADATA_MARKERS)

def dotnet_behavior_tags(blob: str) -> list[str]:
    low = scanner_contract_lower_token(blob, replacement='')
    return [tag for tag, marker in DOTNET_BEHAVIOR_MARKERS if marker in low]

def dotnet_extension_tags(ext: str) -> list[str]:
    if scanner_contract_lower_token(ext, replacement='') in DOTNET_EXTENSION_MISMATCH_EXTENSIONS:
        return ['extension_mismatch', 'binary_failover_dotnet_metadata']
    return []

__all__ = (
    'DOTNET_BEHAVIOR_MARKERS',
    'DOTNET_EXTENSIONS',
    'DOTNET_EXTENSION_MISMATCH_EXTENSIONS',
    'DOTNET_METADATA_MARKERS',
    'dotnet_behavior_tags',
    'dotnet_extension_tags',
    'dotnet_metadata_present',
)
