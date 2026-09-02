"""Stage2636.11 bounded final attack-intelligence publication contracts."""
from __future__ import annotations
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import (
    unavailable_attack_mapping_fixture, unavailable_attack_publication_fixture,
)

import json

from Virus_Scan.detection.correlation.multi_signal.attack_intelligence import (
    compute_attack_intelligence,
)
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_registry import (
    ATTACK_INTELLIGENCE_CLASSIFIERS,
)
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.evidence.full_analysis.result_stage import build_success_result
from Virus_Scan.detection.attack.candidate_retrieval import unavailable_attack_candidate_retrieval
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.publication.json_finalization.success_fields import (
    compact_success_analysis_fields,
)


def test_stage2636_11_final_publication_retains_bounded_classifier_provenance() -> None:
    tags = physical_tag_evidence(("lsass_access", "credential_dump_attempt"), source_detector="stage2636_11_publication")
    attack = compute_attack_intelligence(tags, ())
    chains = evaluate_chain_evidence(tags=tags)
    mapping, candidate, plan, explainability = unavailable_attack_publication_fixture(
        tags, chains, reason="publication_fixture_no_cluster",
    )
    result = build_success_result(
        attack_mapping_result=mapping,
        attack_discovery_plan=plan, attack_explainability=explainability,
        node="sample",
        path="sample.bin",
        score_val=80.0,
        cluster_id=None,
        classification="malicious",
        tags=tags,
        chain_evidence=chains,
        yara_evidence=None,
        strings_blob="",
        api_result={},
        behavior_timeline=(),
        ordered_events=(),
        attack_info=attack,
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
        explanation={},
    )
    record = result.as_result_record()
    assert record["attack_intelligence"]["evidence_version"] == attack["evidence_version"]

    compact = compact_success_analysis_fields(
        record, {"explanation": {}, "reasons": []},
    )["attack_intelligence"]
    assert compact["evidence_version"] == attack["evidence_version"]
    assert compact["policy_version"] == attack["policy_version"]
    assert compact["calibration_version"] == attack["calibration_version"]
    assert compact["evaluation_provenance"] == attack["evaluation_provenance"]
    assert compact["aggregate_method"] == attack["aggregate_method"]
    assert compact["aggregate_probability"] == attack["aggregate_probability"]
    assert compact["family_probabilities"] == attack["family_probabilities"]
    assert compact["hits"] == list(attack["hits"])

    classifier_records = compact["classifier_records"]
    assert type(classifier_records) is list
    assert len(classifier_records) == len(ATTACK_INTELLIGENCE_CLASSIFIERS)
    credential = next(
        item for item in classifier_records
        if item["family"] == "credential_theft"
    )
    assert credential["matched_root_evidence_ids"]
    assert credential["matched_canonical_tag_ids"]
    assert "rejected_reasons" in credential
    assert "classifier_version" in credential
    assert "family_probability" in credential

    encoded = json.dumps(compact, sort_keys=True, separators=(",", ":"))
    assert len(encoded) < 24000
