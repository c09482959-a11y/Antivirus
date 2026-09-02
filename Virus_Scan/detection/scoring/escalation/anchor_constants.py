"""Immutable high-gate constants for scoring escalation."""
from __future__ import annotations

from Virus_Scan.detection.registries.context import detection_registry_value

HIGH_GATE_VERSION = str(detection_registry_value("HIGH_GATE_VERSION", "anchor_chain_high_gate_v2_high_unlocking_chains"))
HIGH_GATE_MAX_WITHOUT_AUTHORITY = float(detection_registry_value("HIGH_GATE_MAX_WITHOUT_AUTHORITY", 49.0))
HIGH_GATE_SINGLE_ANCHOR_TAGS = frozenset(detection_registry_value("HIGH_GATE_SINGLE_ANCHOR_TAGS", ("c2_beacon", "remote_command_channel", "mimikatz_credential_dump", "high_confidence_credential_theft", "high_confidence_browser_credential_theft")))
HIGH_GATE_WEAK_OR_STRUCTURAL_TAGS = frozenset(detection_registry_value("HIGH_GATE_WEAK_OR_STRUCTURAL_TAGS", ("high_entropy", "packed_or_obfuscated", "structural_anomaly")))

__all__ = (
    "HIGH_GATE_MAX_WITHOUT_AUTHORITY",
    "HIGH_GATE_SINGLE_ANCHOR_TAGS",
    "HIGH_GATE_VERSION",
    "HIGH_GATE_WEAK_OR_STRUCTURAL_TAGS",
)
