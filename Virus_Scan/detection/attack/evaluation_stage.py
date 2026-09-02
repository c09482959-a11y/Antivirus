"""Single official ATT&CK evaluation owner for one frozen evidence generation."""
from __future__ import annotations

from Virus_Scan.contracts.artifact_evidence_snapshot import ArtifactEvidenceSnapshot
from Virus_Scan.detection.attack.mapping.contracts import AttackMappingResult
from Virus_Scan.detection.attack.mapping.mapper import map_attack_evidence
from Virus_Scan.detection.attack.versioning import (
    ATTACK_EVALUATION_PROVENANCE,
    ATTACK_MAPPING_POLICY_VERSION,
)
from Virus_Scan.runtime.api import mitre_runtime_snapshot


def unavailable_attack_mapping_result(reason: str) -> AttackMappingResult:
    """Return the one canonical unavailable official ATT&CK result."""
    if type(reason) is not str or not reason or len(reason) > 256:
        raise ValueError("official_attack_unavailable_reason_invalid")
    return AttackMappingResult(
        repository_digest="",
        dataset_version="",
        decisions=(),
        probability=0.0,
        probability_unavailable_reason="",
        ready=False,
        unavailable_reason=str.__str__(reason),
        policy_version=ATTACK_MAPPING_POLICY_VERSION,
        evaluation_provenance=ATTACK_EVALUATION_PROVENANCE,
    )


def evaluate_final_attack_mapping(
    evidence: ArtifactEvidenceSnapshot,
) -> AttackMappingResult:
    """Evaluate official ATT&CK exactly once from the final evidence snapshot."""
    if type(evidence) is not ArtifactEvidenceSnapshot:
        raise TypeError("final_artifact_evidence_snapshot_required")
    runtime = mitre_runtime_snapshot()
    if not runtime.enabled:
        return unavailable_attack_mapping_result("mitre_disabled")
    if runtime.repository is None:
        reason = runtime.status.get("unavailable_reason", "mitre_repository_unavailable")
        if type(reason) is not str or not reason or len(reason) > 256:
            reason = "mitre_repository_unavailable"
        return unavailable_attack_mapping_result(reason)
    return map_attack_evidence(runtime.repository, evidence)


__all__ = (
    "evaluate_final_attack_mapping",
    "unavailable_attack_mapping_result",
)
