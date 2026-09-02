"""Stage2636.10014 production-path ATT&CK publication contracts."""
from __future__ import annotations
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import (
    unavailable_attack_mapping_fixture, unavailable_attack_publication_fixture,
)

import ast
from pathlib import Path

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.attack.candidate_retrieval import unavailable_attack_candidate_retrieval
from Virus_Scan.detection.attack.publication import (
    parse_official_attack_probability_evidence,
)
from Virus_Scan.detection.evidence.full_analysis.result_stage import (
    build_success_result,
)
from Virus_Scan.detection.scoring.full_analysis.score_explained import (
    ScoreExplainedRequest,
    score_explained,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import (
    normalize_tag_evidence,
)
from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.runtime.api import release_mitre_runtime


def _score_context() -> tuple[object, ChainEvidence, float, dict[str, object]]:
    release_mitre_runtime()
    tags = normalize_tag_evidence(())
    chains = evaluate_chain_evidence(tags=tags)
    score, explanation = score_explained(
        ScoreExplainedRequest(
            attack_mapping_result=unavailable_attack_mapping_fixture(),
            tags=tags,
            chain_evidence=chains,
            yara_evidence=None,
        )
    )
    return tags, chains, score, explanation


def test_stage2636_10014_active_score_owner_computes_official_attack_evidence() -> None:
    _tags, _chains, score, explanation = _score_context()
    assert score == 0.0
    assert explanation["feature_probabilities"] == {
        "mitre": 0.0,
        "mitre_unavailable_reason": "mitre_official_mapping_unavailable",
    }
    evidence = parse_official_attack_probability_evidence(
        explanation["mitre_evidence_json"]
    )
    assert evidence["mapping_scope"] == "official_attack_techniques"
    assert evidence["ready"] is False
    assert evidence["probability"] == 0.0
    assert evidence["technique_ids_claimed"] is False


def test_stage2636_10014_compact_final_json_retains_official_attack_evidence() -> None:
    tags, chains, score, explanation = _score_context()
    mapping, candidate, plan, explainability = unavailable_attack_publication_fixture(
        tags, chains, reason="publication_fixture_no_cluster",
    )
    result = build_success_result(
        attack_mapping_result=mapping,
        attack_discovery_plan=plan, attack_explainability=explainability,
        node="sample",
        path="sample.bin",
        score_val=score,
        cluster_id=None,
        classification="clean",
        tags=tags,
        chain_evidence=chains,
        yara_evidence=None,
        strings_blob="",
        api_result={},
        behavior_timeline=(),
        ordered_events=(),
        attack_info={},
        attack_candidate_retrieval=candidate.to_record(),
        heur={},
        layer_report={},
        graph_features={},
        temporal_features={},
        markov_features={},
        engine_context={},
        engine_confidence={},
        baseline_maturity={},
        profile_context={},
        evidence_provenance={},
        analytical_calibration={},
        active_profile="other",
        vector=(),
        explanation=explanation,
    )
    compact = compact_result_record(result.as_result_record())
    model_evidence = compact["model_evidence"]
    assert model_evidence["feature_probabilities"]["mitre"] == 0.0
    assert model_evidence["unavailable_reasons"]["mitre"] == (
        "mitre_official_mapping_unavailable"
    )
    evidence = model_evidence["mitre_evidence"]
    assert evidence["mapping_scope"] == "official_attack_techniques"
    assert evidence["ready"] is False
    assert evidence["probability"] == 0.0
    assert model_evidence["evidence_discovery_plan"]["evidence_authority"] == "context_only"
    assert compact["attack_explainability"]["projection_role"] == "explainability_only"
    assert "feature_probabilities" not in compact["explanation"]
    assert "mitre_evidence_json" not in compact["explanation"]


def test_stage2636_10014_evaluator_does_not_construct_internal_attack_evidence() -> None:
    path = Path("tools/evaluation/evaluate_mitre_attack_mapping.py")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = {
        alias.name
        for node in ast.walk(tree)
        if type(node) in (ast.Import, ast.ImportFrom)
        for alias in node.names
    }
    forbidden = {
        "TagEvidence",
        "ChainEvidence",
        "ChainDecision",
        "map_attack_evidence",
        "mitre_probability_component",
        "official_attack_probability_evidence",
    }
    assert names.isdisjoint(forbidden)
