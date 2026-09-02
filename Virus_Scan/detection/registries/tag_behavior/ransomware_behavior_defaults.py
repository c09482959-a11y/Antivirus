"""Ransomware tag-to-behavior defaults."""
from __future__ import annotations

from Virus_Scan.detection.registries.immutability import freeze_registry_value

RANSOMWARE_TAG_TO_BEHAVIOR = freeze_registry_value({'backup_delete': 'ransomware_behavior',
 'crypto_address_display': 'ransomware_behavior',
 'crypto_file_operation': 'ransomware_behavior',
 'file_rename_delete': 'ransomware_behavior',
 'file_traversal': 'ransomware_behavior',
 'ransom_note_indicator': 'ransomware_behavior',
 'rapid_file_write': 'ransomware_behavior',
 'recovery_disable': 'ransomware_behavior',
 'shadowcopy_delete': 'ransomware_behavior'})

__all__ = ("RANSOMWARE_TAG_TO_BEHAVIOR",)
