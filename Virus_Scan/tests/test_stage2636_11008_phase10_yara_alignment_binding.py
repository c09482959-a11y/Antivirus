"""Phase 10 exact YARA-to-ATT&CK alignment binding regressions."""
from __future__ import annotations

from dataclasses import replace

import pytest

from Virus_Scan.contracts.detection_observation import (
    DetectionObservation,
    ObservationSourceLocation,
)
from Virus_Scan.contracts.yara_hits import YaraRuleIdentity
from Virus_Scan.detection.attack.yara_alignment import (
    canonical_yara_alignment_platform,
    project_yara_observations,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import (
    normalize_tag_evidence,
)
from Virus_Scan.tests.support.canonical_yara_fixtures import (
    candidate_mitre_alignment,
    canonical_test_yara_result,
)


def _platform_tags(*platforms: str):
    observations = tuple(
        DetectionObservation.create(
            tag="powershell_exec",
            producer_id="phase10_platform_fixture",
            stage_id="static_analysis",
            modality="static_structure",
            platform=platform,
            artifact_identity="sha256:phase10-platform-fixture",
            source_location=ObservationSourceLocation(
                "fixture_event", locator="sample.bin", event_id=f"platform-{index}",
            ),
            integrity_status="verified",
            directness="direct",
            confidence=1.0,
        )
        for index, platform in enumerate(platforms)
    )
    return normalize_tag_evidence(observations)


def test_alignment_rejects_noncanonical_manifest_and_requirement_digests() -> None:
    result = canonical_test_yara_result()
    alignment = candidate_mitre_alignment(result.hits[0])

    with pytest.raises(ValueError, match="implementation_manifest_digest_mismatch"):
        replace(alignment, implementation_manifest_digest="0" * 64)
    with pytest.raises(ValueError, match="policy_digest_mismatch"):
        replace(alignment, policy_digest="0" * 64)
    with pytest.raises(ValueError, match="requirement_digests_mismatch"):
        replace(alignment, requirement_digests=("0" * 64,))


def test_alignment_projection_is_bound_to_exact_rule_and_repository_identity() -> None:
    result = canonical_test_yara_result()
    alignment = candidate_mitre_alignment(result.hits[0])

    assert len(project_yara_observations(
        result,
        alignments=(alignment,),
        platform="windows",
        repository_digest=alignment.repository_digest,
    )) == 1
    assert project_yara_observations(
        result,
        alignments=(alignment,),
        platform="windows",
        repository_digest="0" * 64,
    ) == ()

    identity = replace(
        result.hits[0].rule_identity,
        semantic_metadata_digest="0" * 64,
    )
    changed_hit = replace(result.hits[0], rule_identity=identity)
    changed_result = replace(result, hits=(changed_hit,))
    assert project_yara_observations(
        changed_result,
        alignments=(alignment,),
        platform="windows",
        repository_digest=alignment.repository_digest,
    ) == ()

    tagged_identity = replace(
        result.hits[0].rule_identity,
        rule_tags=("changed_tag",),
    )
    tagged_hit = replace(result.hits[0], rule_identity=tagged_identity)
    tagged_result = replace(result, hits=(tagged_hit,))
    assert project_yara_observations(
        tagged_result,
        alignments=(alignment,),
        platform="windows",
        repository_digest=alignment.repository_digest,
    ) == ()


def test_required_match_details_fail_closed_until_physical_contract_supports_them() -> None:
    result = canonical_test_yara_result()
    alignment = replace(
        candidate_mitre_alignment(result.hits[0]),
        required_match_detail_fields=("match_offsets",),
    )

    assert project_yara_observations(
        result,
        alignments=(alignment,),
        platform="windows",
        repository_digest=alignment.repository_digest,
    ) == ()


def test_platform_context_is_explicit_and_conflicts_fail_closed() -> None:
    assert canonical_yara_alignment_platform(_platform_tags("Windows")) == "windows"
    assert canonical_yara_alignment_platform(_platform_tags("Windows", "Linux")) == ""
    assert canonical_yara_alignment_platform(_platform_tags("")) == ""


def test_mapping_eligibility_requires_logic_and_semantic_metadata_identity() -> None:
    identity = canonical_test_yara_result().hits[0].rule_identity
    assert identity.mapping_eligible is True
    assert replace(identity, logic_hash="").mapping_eligible is False
    assert replace(identity, semantic_metadata_digest="").mapping_eligible is False

    with pytest.raises(TypeError, match="yara_alignment_platform_evidence_required"):
        canonical_yara_alignment_platform(())
