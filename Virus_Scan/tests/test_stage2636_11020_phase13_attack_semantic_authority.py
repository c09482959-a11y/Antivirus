"""Phase 13: ATT&CK implementation requirements own four-state semantics."""
from __future__ import annotations

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.detection.attack.api import serialize_official_attack_probability_evidence
from Virus_Scan.detection.attack.evaluation_contracts import (
    AttackEvaluationSample,
    AttackTechniqueExpectation,
)
from Virus_Scan.detection.attack.mapping.mapper import map_attack_evidence
from Virus_Scan.detection.attack.mapping.registry import (
    ATTACK_TECHNIQUE_POLICIES,
    ATTACK_TECHNIQUE_POLICY_BY_ID,
)
from Virus_Scan.detection.attack.publication import (
    parse_official_attack_probability_evidence,
)
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.publication.mitre_summary import build_mitre_findings_summary
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import (
    attack_chain_contract_fixture,
    attack_contract_repository,
    attack_explainability_context_fixture,
    attack_mapping_evidence_fixture,
)
from tools.evaluation.attack_production_reconciliation import _outcome


_EXPECTED_ADMISSION_STATES = {
    "T1003": "candidate_only",
    "T1021": "candidate_only",
    "T1041": "unsupported_by_sensors",
    "T1055": "candidate_only",
    "T1059": "unsupported_by_sensors",
    "T1059.001": "candidate_only",
    "T1105": "candidate_only",
    "T1562.001": "retired",
}


def _evidence_and_mapping(
    *, limitations: tuple[str, ...] = (), chains: ChainEvidence | None = None,
):
    evidence = attack_mapping_evidence_fixture(
        TagEvidence(),
        chains if chains is not None else ChainEvidence("phase13-empty-v1", "phase13-empty"),
        limitations=limitations,
        completeness="partial" if limitations else "complete",
    )
    return evidence, map_attack_evidence(attack_contract_repository(), evidence)


def _mapping(*, limitations: tuple[str, ...] = (), chains: ChainEvidence | None = None):
    return _evidence_and_mapping(limitations=limitations, chains=chains)[1]


def _decision(mapping, technique_id: str):
    return next(item for item in mapping.decisions if item.technique_id == technique_id)


def _publication_record(mapping) -> dict[str, object]:
    repository = attack_contract_repository()
    repository_status = repository.to_record()
    repository_status.update({
        "unavailable_reason": "",
        "lock_state": "active_files_locked",
        "config_state": "parent_validated_readonly",
        "refresh_state": "worker_readonly",
        "active_cache_source": "offline_active_cache",
        "api_identity_checked": False,
        "sha1_verification_state": "local_git_blob_recomputed",
        "integrity_state": "semantic_and_local_integrity_valid",
        "locked_resource_count": 1,
        "activation_state": "candidate_validated",
        "activation_digest": "9" * 64,
        "activation_counts": {
            "active_alignments": 0,
            "quarantined_alignments": 0,
            "active_implementations": 0,
            "quarantined_implementations": 0,
            "active_policies": 0,
            "quarantined_policies": 0,
            "retired_policies": 0,
            "active_calibrations": 0,
            "quarantined_calibrations": 0,
        },
        "enabled": True,
        "available": True,
    })
    record = mapping.to_record()
    record.update({
        "mapping_scope": "official_attack_techniques",
        "technique_ids_claimed": bool(record["confirmed"]),
        "repository_status": repository_status,
        "verified_yara_observation_count": 0,
        "yara_alignment_count": 0,
    })
    return record


def test_phase13_reviewed_admission_states_are_unchanged() -> None:
    assert {
        policy.technique_id: policy.admission_state
        for policy in ATTACK_TECHNIQUE_POLICIES
    } == _EXPECTED_ADMISSION_STATES


def test_phase13_unavailable_is_distinct_from_complete_negative_and_retired() -> None:
    mapping = _mapping()
    t1041 = _decision(mapping, "T1041")
    t1059 = _decision(mapping, "T1059")
    t1003 = _decision(mapping, "T1003")
    retired = _decision(mapping, "T1562.001")

    for decision in (t1041, t1059):
        assert decision.status == "unavailable"
        assert decision.unavailable_reason == "unsupported_by_sensors"
        assert decision.rejection_reason == ""
        assert decision.probability == 0.0
        assert decision.execution_observed is False
    assert t1003.status == "rejected"
    assert t1003.rejection_reason == "insufficient_implementation_evidence"
    assert t1003.unavailable_reason == ""
    assert retired.status == "rejected"
    assert retired.rejection_reason == "mapping_retired"
    assert retired.unavailable_reason == ""


def test_phase13_required_analysis_deferral_is_unavailable_not_false_negative() -> None:
    policy = ATTACK_TECHNIQUE_POLICY_BY_ID["T1003"]
    chains = attack_chain_contract_fixture(
        policy, "phase13-semantic-authority", status="confirmed", root_count=2,
    )
    mapping = _mapping(
        chains=chains,
        limitations=(
            "evidence_discovery_unavailable:implementation:local.t1003.lsass_dump:"
            "chain:anchor:api_lsass_minidump:step:0:operation:deferred_resource_budget",
        ),
    )
    decision = _decision(mapping, "T1003")
    assert decision.status == "unavailable"
    assert decision.unavailable_reason == "required_analysis_unavailable"
    assert decision.rejection_reason == ""
    assert decision.root_evidence_ids
    assert decision.evidence_ids
    assert decision.execution_observed is False


def test_phase13_publication_round_trip_preserves_unavailable_bucket_and_reason() -> None:
    evidence = _publication_record(_mapping())
    encoded = serialize_official_attack_probability_evidence(evidence)
    parsed = parse_official_attack_probability_evidence(encoded)
    unavailable = {
        item["technique_id"]: item for item in parsed["unavailable"]
    }
    assert tuple(sorted(unavailable)) == ("T1041", "T1059")
    assert unavailable["T1041"]["unavailable_reason"] == "unsupported_by_sensors"
    assert unavailable["T1041"]["rejection_reason"] == ""
    assert all(item["status"] == "unavailable" for item in unavailable.values())


def test_phase13_mitre_summary_projects_decision_unavailability_without_translation() -> None:
    artifact_evidence, mapping = _evidence_and_mapping()
    evidence = _publication_record(mapping)
    _candidate, _plan, explainability = attack_explainability_context_fixture(
        artifact_evidence, mapping, reason="phase13_summary_projection",
    )
    summary = build_mitre_findings_summary(
        scan_id="phase13-semantic-authority",
        snapshot_semantic_digest="8" * 64,
        local_results={
            "sample.bin": {
                "sha256": "a" * 64,
                "classification": "benign_clean",
                "score": 0.0,
                "model_evidence": {"mitre_evidence": evidence},
                "canonical_chain_evidence": artifact_evidence.chain_evidence.to_record(),
                "attack_explainability": explainability.to_record(),
            },
        },
    )
    counts = summary.counts_record()
    assert counts["decision_count"] == 8
    assert counts["unavailable_decision_count"] == 2
    rows = {row.technique_id: row for row in summary.finding_rows}
    assert rows["T1041"].decision_status == "unavailable"
    assert rows["T1041"].unavailable_reason == "unsupported_by_sensors"
    assert rows["T1041"].rejection_reason == ""
    assert rows["T1003"].decision_status == "rejected"
    assert rows["T1003"].rejection_reason == "insufficient_implementation_evidence"
    assert rows["T1003"].unavailable_reason == ""


def test_phase13_production_reconciliation_consumes_same_unavailable_state_and_reason() -> None:
    decision = _decision(_mapping(), "T1041")
    expectation = AttackTechniqueExpectation(
        technique_id="T1041",
        expected_state="unavailable",
        label_rationale="artifact behavior present but local sensors unsupported",
        label_evidence_refs=("artifact-byte-oracle",),
        supported_claim_scope="unavailable",
        platform="windows",
        modality="unavailable",
    )
    sample = AttackEvaluationSample(
        sample_id="phase13-reconciliation",
        partition="development",
        source_family="phase13",
        related_group="phase13",
        package_campaign_id="phase13",
        collection_session="phase13",
        malware_class="control",
        sample_category="unsupported_or_unavailable",
        artifact_path="/tmp/phase13-reconciliation.bin",
        artifact_sha256="a" * 64,
        artifact_size=1,
        acquisition_provenance="synthetic_engineering",
        collected_at="2026-08-17T00:00:00Z",
        platform="windows",
        file_type="bin",
        technique_expectations=(expectation,),
        evidence_domain="synthetic_engineering",
        eligible_for_production_metrics=False,
        eligible_for_policy_promotion=False,
        eligible_for_production_calibration=False,
    )
    outcomes = _outcome(sample, {"T1041": decision.to_record()})
    assert len(outcomes) == 1
    outcome = outcomes[0]
    assert outcome.expected_state == "unavailable"
    assert outcome.observed_state == "unavailable"
    assert outcome.state_matches is True
    assert outcome.unavailable_reason == "unsupported_by_sensors"
    assert outcome.rejection_reason == ""
