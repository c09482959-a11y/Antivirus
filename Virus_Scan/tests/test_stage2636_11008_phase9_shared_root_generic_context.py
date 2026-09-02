"""Stage2636.11008 Phase 9 shared-root YARA semantic projection gates."""
from __future__ import annotations
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture

import json

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.detection.attack.yara_alignment import project_yara_observations
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence import (
    compute_attack_intelligence,
)
from Virus_Scan.detection.scoring.adaptive.evidence_projection import (
    build_probability_features,
)
from Virus_Scan.detection.scoring.weighting.static_layer import (
    compute_quick_static_layer,
)
from Virus_Scan.detection.scoring.yara.context_evidence import (
    generic_yara_evidence_context,
)
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.tests.support.canonical_yara_fixtures import (
    candidate_mitre_alignment,
    canonical_test_yara_result,
    family_alignment,
)


def _empty_chains() -> ChainEvidence:
    return ChainEvidence("stage2636_11008_phase9", "0" * 64)


def test_one_physical_root_is_preserved_across_all_authorized_projections() -> None:
    result = canonical_test_yara_result(rule_name="stage2636_exfiltration")
    hit = result.hits[0]
    generic = generic_yara_evidence_context(result)
    attack = compute_attack_intelligence(
        physical_tag_evidence(("collection", "http_upload")),
        result,
        yara_family_alignments=(family_alignment(hit),),
    )
    alignment = candidate_mitre_alignment(hit)
    observations = project_yara_observations(
        result,
        alignments=(alignment,),
        platform="windows",
        repository_digest=alignment.repository_digest,
    )
    attack_record = next(
        item for item in attack["classifier_records"]
        if item["family"] == "exfiltration"
    )

    assert generic.root_observation_ids == (hit.root_observation_id,)
    assert attack_record["matched_root_evidence_ids"].count(hit.root_observation_id) == 1
    assert observations[0].root_observation_id == hit.root_observation_id
    assert generic.probability_authority is False


def test_generic_yara_context_never_creates_probability_or_quick_static_points() -> None:
    result = canonical_test_yara_result(rule_name="Mimikatz_Ransom_Loader")
    tags = physical_tag_evidence(())
    chains = _empty_chains()

    features = build_probability_features(
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        tags=tags,
        yara_hits=result,
        chain_evidence=chains,
    )
    quick = compute_quick_static_layer(tags, chains, result)

    assert features["p_yara"] == 0.0
    assert features["p_yara_unavailable_reason"] == (
        "yara_production_calibration_unavailable"
    )
    context = json.loads(features["yara_evidence_context_json"])
    assert context["root_observation_ids"] == [result.hits[0].root_observation_id]
    assert context["rule_identity_digests"] == [result.hits[0].rule_identity.digest]
    assert context["probability_authority"] is False
    assert quick["score"] == 0.0
    assert "yara_static_match" not in quick["hits"]


def test_noncomplete_or_unverified_yara_is_explicit_zero_authority() -> None:
    result = canonical_test_yara_result(verified=False)
    context = generic_yara_evidence_context(result)
    features = build_probability_features(
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        tags=physical_tag_evidence(()),
        yara_hits=result,
        chain_evidence=_empty_chains(),
    )

    assert context.root_observation_ids == ()
    assert context.probability_authority is False
    assert context.probability_unavailable_reason == "yara_verified_execution_required"
    assert features["p_yara"] == 0.0
    assert features["p_yara_unavailable_reason"] == "yara_verified_execution_required"
