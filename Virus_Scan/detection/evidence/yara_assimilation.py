"""Canonical reviewed-YARA assimilation into artifact evidence.

Physical YARA hits remain owned by :mod:`Virus_Scan.contracts.yara_hits` and the
reviewed alignment registry remains the only interpreter of those hits.  This
module owns the single production transition from reviewed YARA observations
into canonical TagEvidence.  It performs no ATT&CK mapping and no Chain
mapping; downstream canonical evidence owners consume the merged TagEvidence
normally.
"""
from __future__ import annotations

from Virus_Scan.contracts.yara_hits import YaraScanResult, canonical_yara_scan_result
from Virus_Scan.detection.attack.yara_alignment import (
    YARA_OBSERVATION_ALIGNMENTS,
    YaraObservationAlignmentSpec,
    project_yara_observations,
)
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.tags.evidence_generation import merge_tag_evidence_inputs
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence


def assimilate_reviewed_yara_evidence(
    tags: TagEvidence,
    scan_result: object,
    *,
    platform: str,
    repository_digest: str,
    alignments: tuple[YaraObservationAlignmentSpec, ...] = YARA_OBSERVATION_ALIGNMENTS,
) -> TagEvidence:
    """Merge exactly reviewed physical YARA observations into TagEvidence.

    This function is deliberately incapable of evaluating Chains or ATT&CK.
    Model/context projections are not accepted.  If no reviewed observation is
    physically established, the original TagEvidence object is returned by
    identity so callers do not create a spurious evidence generation.
    """
    if type(tags) is not TagEvidence:
        raise TypeError("reviewed_yara_assimilation_tag_evidence_required")
    if type(platform) is not str:
        raise TypeError("reviewed_yara_assimilation_platform_required")
    if type(repository_digest) is not str:
        raise TypeError("reviewed_yara_assimilation_repository_digest_required")
    result = canonical_yara_scan_result(scan_result)
    if type(result) is not YaraScanResult:
        raise TypeError("reviewed_yara_assimilation_scan_result_required")
    observations = project_yara_observations(
        result,
        alignments=alignments,
        platform=platform,
        repository_digest=repository_digest,
    )
    if not observations:
        return tags
    yara_tags = normalize_tag_evidence(
        observations,
        source_detector="yara_match",
        source_stage="yara_scan",
    )
    return merge_tag_evidence_inputs((tags, yara_tags))


__all__ = (
    "assimilate_reviewed_yara_evidence",
)
