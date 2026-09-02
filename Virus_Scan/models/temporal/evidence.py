"""Immutable temporal policy vocabulary and bounded evidence helpers."""
from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.models.contracts.no_hook_materialization import (
    no_hook_finite_float,
)
from Virus_Scan.models.temporal.text_boundary import temporal_boundary_text

TEMPORAL_PHASE_ORDER = (
    "execution", "persistence", "lateral_movement", "exfiltration",
)
TEMPORAL_TAG_PHASES = MappingProxyType({
    "powershell_exec": "execution",
    "cmd_exec": "execution",
    "mshta_exec": "execution",
    "rundll32_exec": "execution",
    "regsvr32_exec": "execution",
    "certutil_exec": "execution",
    "dll_load": "execution",
    "process_injection": "execution",
    "memory_write": "execution",
    "thread_execution": "execution",
    "memory_protect": "execution",
    "encoded_powershell": "execution",
    "scheduled_task": "persistence",
    "scheduled_execution": "persistence",
    "schtasks": "persistence",
    "schtasks_create": "persistence",
    "registry_persistence": "persistence",
    "startup_persistence": "persistence",
    "defender_disable": "persistence",
    "shadowcopy_delete": "persistence",
    "wmi_exec": "lateral_movement",
    "admin_share_access": "lateral_movement",
    "smb_activity": "lateral_movement",
    "remote_execution": "lateral_movement",
    "lateral_movement": "lateral_movement",
    "network_download": "exfiltration",
    "network_activity": "exfiltration",
    "network_exfiltration": "exfiltration",
    "http_upload": "exfiltration",
    "dns_tunneling": "exfiltration",
    "encoded_payload_candidate": "exfiltration",
})
TEMPORAL_HIGH_RISK_TAGS = frozenset({
    "process_injection", "memory_write", "thread_execution",
    "memory_protect", "certutil_exec", "powershell_exec",
    "encoded_powershell", "defender_disable", "shadowcopy_delete",
    "wmi_exec", "admin_share_access", "smb_activity", "dns_tunneling",
    "credential_dump_attempt", "lsass_access", "mimikatz_credential_dump",
    "encoded_payload_candidate",
})


def finite_temporal_model_metric(
    value: object, *, default: object = 0.0,
) -> object:
    """Return finite evidence or an explicit invalid-input reason."""
    numeric, reason = no_hook_finite_float(
        value,
        default=default,
        reason="non_numeric_temporal_model_metric",
        non_finite_reason="non_finite_temporal_model_metric",
    )
    if reason is not None and reason != "":
        return numeric, reason
    return numeric, None


def cache_key(namespace: object, *parts: object) -> object:
    return (
        temporal_boundary_text(
            namespace, default="temporal_text_unavailable"
        )
        + ":"
        + ":".join(
            temporal_boundary_text(
                part, default="temporal_text_unavailable"
            ) for part in parts
        )
    )


__all__ = (
    "TEMPORAL_HIGH_RISK_TAGS",
    "TEMPORAL_PHASE_ORDER",
    "TEMPORAL_TAG_PHASES",
    "cache_key",
    "finite_temporal_model_metric",
)
