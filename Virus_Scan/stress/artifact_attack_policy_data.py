"""Immutable ATT&CK evaluation policy data shared by independent byte oracles.

This module contains policy data only.  It does not evaluate production evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.detection.attack.implementations import ATTACK_ANALYTIC_IMPLEMENTATIONS


@dataclass(frozen=True, slots=True)
class ArtifactAttackRelationRequirement:
    """Frozen evaluation-only causal relation required for artifact behavior."""

    source_operation_kind: str
    sink_operation_kind: str
    require_connected: bool = True
    require_same_resource: bool = False

    def to_record(self) -> dict[str, object]:
        return {
            "require_connected": self.require_connected,
            "require_same_resource": self.require_same_resource,
            "sink_operation_kind": self.sink_operation_kind,
            "source_operation_kind": self.source_operation_kind,
        }


@dataclass(frozen=True, slots=True)
class ArtifactAttackRequirement:
    technique_id: str
    required_operations: tuple[str, ...]
    required_resources: tuple[str, ...] = ()
    minimum_process_launch_count: int = 0
    required_relations: tuple[ArtifactAttackRelationRequirement, ...] = ()

    def to_record(self) -> dict[str, object]:
        return {
            "minimum_process_launch_count": self.minimum_process_launch_count,
            "required_operations": self.required_operations,
            "required_relations": tuple(item.to_record() for item in self.required_relations),
            "required_resources": self.required_resources,
            "technique_id": self.technique_id,
        }


ARTIFACT_ATTACK_REQUIREMENTS = (
    ArtifactAttackRequirement("T1003", ("process_open", "memory_read"), ("lsass.exe", "minidumpwritedump")),
    ArtifactAttackRequirement("T1021", ("process_launch",), ("admin$",), minimum_process_launch_count=2),
    ArtifactAttackRequirement("T1041", ("network_send", "network_upload")),
    ArtifactAttackRequirement(
        "T1055",
        ("process_open", "memory_allocate", "memory_write", "thread_execute"),
        required_relations=(
            ArtifactAttackRelationRequirement(
                "memory_allocate", "memory_write", require_same_resource=True,
            ),
            ArtifactAttackRelationRequirement(
                "memory_allocate", "thread_execute", require_same_resource=True,
            ),
        ),
    ),
    ArtifactAttackRequirement("T1059", ("process_launch",), ("cmd.exe",)),
    ArtifactAttackRequirement("T1059.001", ("process_launch",), ("powershell", "-encodedcommand")),
    ArtifactAttackRequirement("T1105", ("network_download", "file_write", "process_launch")),
    ArtifactAttackRequirement("T1562.001", ("security_control_disable",), ("disablerealtimemonitoring",)),
)
ARTIFACT_ATTACK_REQUIREMENT_BY_ID = MappingProxyType({item.technique_id: item for item in ARTIFACT_ATTACK_REQUIREMENTS})
ATTACK_ADMISSION_BY_TECHNIQUE = MappingProxyType({item.technique_id: item.admission_state for item in ATTACK_ANALYTIC_IMPLEMENTATIONS})

def _policy_digest() -> str:
    # The digest input is ephemeral and derived entirely from immutable module
    # owners; no mutable module-level policy representation survives.
    record = {
        "admission": tuple(sorted(ATTACK_ADMISSION_BY_TECHNIQUE.items())),
        "requirements": tuple(item.to_record() for item in ARTIFACT_ATTACK_REQUIREMENTS),
        "version": "stage2636_11020_artifact_attack_oracle_policy_v2",
    }
    return canonical_json_sha256(record)


ARTIFACT_ATTACK_ORACLE_POLICY_DIGEST = _policy_digest()

__all__ = (
    "ARTIFACT_ATTACK_ORACLE_POLICY_DIGEST",
    "ARTIFACT_ATTACK_REQUIREMENTS",
    "ARTIFACT_ATTACK_REQUIREMENT_BY_ID",
    "ATTACK_ADMISSION_BY_TECHNIQUE",
    "ArtifactAttackRelationRequirement",
    "ArtifactAttackRequirement",
)
