"""Lateral Movement tag-to-behavior defaults."""
from __future__ import annotations

from Virus_Scan.detection.registries.immutability import freeze_registry_value

LATERAL_MOVEMENT_TAG_TO_BEHAVIOR = freeze_registry_value({'admin_share_access': 'lateral_movement',
 'impacket_exec': 'lateral_movement',
 'rdp_enable_or_use': 'lateral_movement',
 'remote_execution': 'lateral_movement',
 'smb_activity': 'lateral_movement',
 'win32_process_create': 'wmi_exec',
 'winrm_exec': 'winrm_exec',
 'wmi': 'wmi_exec',
 'wmi_exec': 'wmi_exec',
 'wmic': 'wmi_exec'})

__all__ = ("LATERAL_MOVEMENT_TAG_TO_BEHAVIOR",)
