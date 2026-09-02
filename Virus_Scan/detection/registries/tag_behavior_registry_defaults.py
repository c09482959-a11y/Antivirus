"""Composed bounded tag behavior registry defaults.

Tag patterns, attack graph defaults, and tag-to-behavior mappings are split into
domain-owned registry shards and composed here as a frozen read-only view.
"""
from __future__ import annotations

from Virus_Scan.detection.registries.immutability import freeze_registry_value
from Virus_Scan.detection.registries.tag_behavior.graph_defaults import ATTACK_GRAPH
from Virus_Scan.detection.registries.tag_behavior.pattern_defaults import TAG_PATTERNS
from Virus_Scan.detection.registries.tag_behavior.credential_behavior_defaults import CREDENTIAL_TAG_TO_BEHAVIOR
from Virus_Scan.detection.registries.tag_behavior.execution_behavior_defaults import EXECUTION_TAG_TO_BEHAVIOR
from Virus_Scan.detection.registries.tag_behavior.network_behavior_defaults import NETWORK_TAG_TO_BEHAVIOR
from Virus_Scan.detection.registries.tag_behavior.evasion_behavior_defaults import EVASION_TAG_TO_BEHAVIOR
from Virus_Scan.detection.registries.tag_behavior.persistence_behavior_defaults import PERSISTENCE_TAG_TO_BEHAVIOR
from Virus_Scan.detection.registries.tag_behavior.ransomware_behavior_defaults import RANSOMWARE_TAG_TO_BEHAVIOR
from Virus_Scan.detection.registries.tag_behavior.media_archive_pickle_behavior_defaults import MEDIA_ARCHIVE_PICKLE_TAG_TO_BEHAVIOR
from Virus_Scan.detection.registries.tag_behavior.dotnet_reflection_behavior_defaults import DOTNET_REFLECTION_TAG_TO_BEHAVIOR
from Virus_Scan.detection.registries.tag_behavior.lateral_movement_behavior_defaults import LATERAL_MOVEMENT_TAG_TO_BEHAVIOR
from Virus_Scan.detection.registries.tag_behavior.misc_behavior_defaults import MISC_TAG_TO_BEHAVIOR

TAG_TO_BEHAVIOR = freeze_registry_value({
    **dict(CREDENTIAL_TAG_TO_BEHAVIOR),
    **dict(EXECUTION_TAG_TO_BEHAVIOR),
    **dict(NETWORK_TAG_TO_BEHAVIOR),
    **dict(EVASION_TAG_TO_BEHAVIOR),
    **dict(PERSISTENCE_TAG_TO_BEHAVIOR),
    **dict(RANSOMWARE_TAG_TO_BEHAVIOR),
    **dict(MEDIA_ARCHIVE_PICKLE_TAG_TO_BEHAVIOR),
    **dict(DOTNET_REFLECTION_TAG_TO_BEHAVIOR),
    **dict(LATERAL_MOVEMENT_TAG_TO_BEHAVIOR),
    **dict(MISC_TAG_TO_BEHAVIOR),
})

__all__ = ("ATTACK_GRAPH", "TAG_PATTERNS", "TAG_TO_BEHAVIOR")
