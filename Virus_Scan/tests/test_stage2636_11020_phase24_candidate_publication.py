"""Phase 24 final-publication isolation for ATT&CK candidate context."""
from __future__ import annotations
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import (
    unavailable_attack_mapping_fixture, unavailable_attack_publication_fixture,
)

from Virus_Scan.detection.attack.candidate_retrieval import (
    unavailable_attack_candidate_retrieval,
)
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.evidence.full_analysis.result_stage import build_success_result
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.publication.json_writer import compact_result_record


def test_phase24_candidate_context_is_separate_from_official_mitre_evidence() -> None:
    tags = normalize_tag_evidence(())
    chains = evaluate_chain_evidence(tags=tags)
    mapping, candidate_result, plan, explainability = unavailable_attack_publication_fixture(
        tags, chains, reason="no_cluster",
    )
    candidate = candidate_result.to_record()
    result = build_success_result(
        attack_mapping_result=mapping,
        attack_discovery_plan=plan, attack_explainability=explainability,
        node="phase24", path="phase24.bin", score_val=0.0, cluster_id=None,
        classification="clean", tags=tags, chain_evidence=chains,
        yara_evidence=None, strings_blob="", api_result={},
        behavior_timeline=(), ordered_events=(), attack_info={},
        attack_candidate_retrieval=candidate, heur={}, layer_report={},
        graph_features={}, temporal_features={}, markov_features={},
        engine_context={}, engine_confidence={}, baseline_maturity={},
        profile_context={}, evidence_provenance={}, analytical_calibration={},
        active_profile="other", vector=(), explanation={},
    )
    compact = compact_result_record(result.as_result_record())
    model = compact["model_evidence"]
    assert model["attack_candidate_retrieval"] == candidate
    assert model["attack_candidate_retrieval"]["eligible_for_probability"] is False
    assert model["evidence_discovery_plan"]["evidence_authority"] == "context_only"
    assert model["evidence_discovery_plan"]["official_decision_effect"] == "none"
    assert compact["attack_explainability"]["projection_role"] == "explainability_only"
    assert compact["attack_explainability"]["official_decision_effect"] == "none"
    assert model.get("mitre_evidence", {}).get("probability", 0.0) == 0.0
    assert "attack_candidate_retrieval" not in model.get("feature_probabilities", {})
