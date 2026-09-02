"""Evasion tag-to-behavior defaults."""
from __future__ import annotations

from Virus_Scan.detection.registries.immutability import freeze_registry_value

EVASION_TAG_TO_BEHAVIOR = freeze_registry_value({'amsi_bypass_attempt': 'defense_evasion',
 'amsi_scanbuffer_patch': 'defense_evasion',
 'anti_sandbox': 'defense_evasion',
 'anti_vm': 'defense_evasion',
 'defender_disable': 'defense_evasion',
 'etw_bypass_attempt': 'defense_evasion',
 'etw_eventwrite_patch': 'defense_evasion',
 'firewall_rule_change': 'defense_evasion',
 'high_entropy_packed': 'packed_or_obfuscated',
 'low_string_visibility': 'packed_or_obfuscated',
 'obfuscated_script': 'packed_or_obfuscated',
 'obfuscation_pack': 'packed_or_obfuscated',
 'packed_exe': 'packed_or_obfuscated',
 'packed_or_obfuscated': 'packed_or_obfuscated',
 'packer_marker': 'packed_or_obfuscated',
 'priv_esc_uac': 'defense_evasion',
 'security_process_kill': 'defense_evasion',
 'security_service_disable': 'defense_evasion',
 'tamper_protection_disable': 'defense_evasion',
 'uac_bypass': 'defense_evasion',
 'very_high_entropy': 'packed_or_obfuscated'})

__all__ = ("EVASION_TAG_TO_BEHAVIOR",)
