from __future__ import annotations

from hashlib import sha256

from Virus_Scan.tests.support.attack_mapping_contract_fixtures import attack_mapping_evidence_fixture

import pytest

from Virus_Scan.contracts.chain_evidence import ChainEvent, ChainEvidence, ChainRule, ChainStep
from Virus_Scan.contracts.detection_observation import ObservationSourceLocation
from Virus_Scan.detection.attack.implementations import (
    ATTACK_ANALYTIC_IMPLEMENTATION_BY_ID,
    ATTACK_ANALYTIC_IMPLEMENTATIONS,
    AttackAnalyticImplementationSpec,
    attack_analytic_implementation_manifest,
)
from Virus_Scan.detection.attack.mapping.mapper import map_attack_evidence
from Virus_Scan.detection.attack.mapping.registry import ATTACK_TECHNIQUE_POLICIES
from Virus_Scan.detection.chains.execution.matching import evaluate_chain_rule
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.registries.chain_registry import CHAIN_RULE_INDEX
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import (
    attack_chain_contract_fixture, attack_contract_repository,
)


def _rule(**changes: object) -> ChainRule:
    values: dict[str, object] = {
        "chain_id": "phase6.correlation",
        "version": "phase6",
        "family": "phase6",
        "match_mode": "anchor",
        "steps": (ChainStep(("first",)), ChainStep(("second",))),
        "minimum_distinct_roots": 2,
        "confidence": 0.9,
        "operational_severity": 50.0,
        "score_points": 0.0,
        "same_target": True,
        "platform_match": True,
        "required_platforms": ("windows",),
        "required_modalities": ("host_telemetry",),
        "minimum_direct_observations": 2,
        "required_fields": ("target_identity",),
        "correlation_group": "phase6",
    }
    values.update(changes)
    return ChainRule(**values)


def _event(
    term: str,
    ordinal: int,
    *,
    root: str,
    target: str = "process:target",
    platform: str = "windows",
    modality: str = "host_telemetry",
    directness: str = "direct",
) -> ChainEvent:
    root_id = "obs_" + sha256(root.encode("utf-8", "strict")).hexdigest()[:40]
    observation_id = "obs_" + sha256(
        f"phase6:{ordinal}:{term}:{root}".encode("utf-8", "strict")
    ).hexdigest()[:40]
    return ChainEvent(
        evidence_id=f"phase6:{ordinal}:{term}",
        root_evidence_id=root_id,
        term=term,
        source="api_observation",
        ordinal=ordinal,
        correlation_group="not_authoritative",
        observation_id=observation_id,
        target_identity=target,
        platform=platform,
        modality=modality,
        source_location=ObservationSourceLocation(
            "fixture_event", locator="phase6", event_id=f"{ordinal}:{term}",
        ),
        integrity_status="verified",
        directness=directness,
    )


def test_explicit_target_correlation_confirms_without_free_form_group_authority() -> None:
    decision = evaluate_chain_rule(
        _rule(),
        (
            _event("first", 0, root="root:first"),
            _event("second", 1, root="root:second"),
        ),
    )
    assert decision is not None
    assert decision.status == "confirmed"
    assert decision.candidate.order_class == "causal_link"
    assert decision.candidate.unmet_requirements == ()


def test_missing_or_mismatched_identity_platform_modality_and_directness_are_candidate() -> None:
    cases = (
        (
            _event("first", 0, root="root:first", target=""),
            _event("second", 1, root="root:second", target=""),
            "same_target_unavailable",
        ),
        (
            _event("first", 0, root="root:first", target="process:a"),
            _event("second", 1, root="root:second", target="process:b"),
            "same_target_mismatch",
        ),
        (
            _event("first", 0, root="root:first", platform="linux"),
            _event("second", 1, root="root:second", platform="linux"),
            "required_platform_unsupported",
        ),
        (
            _event("first", 0, root="root:first", modality="static_string"),
            _event("second", 1, root="root:second", modality="static_string"),
            "required_modality_unsupported",
        ),
        (
            _event("first", 0, root="root:first", directness="inferred"),
            _event("second", 1, root="root:second", directness="inferred"),
            "minimum_direct_observations_unsatisfied",
        ),
    )
    for first, second, reason in cases:
        decision = evaluate_chain_rule(_rule(), (first, second))
        assert decision is not None
        assert decision.status == "candidate"
        assert reason in decision.candidate.unmet_requirements
        assert decision.scoreable


def test_same_physical_root_cannot_satisfy_independent_steps() -> None:
    decision = evaluate_chain_rule(
        _rule(),
        (
            _event("first", 0, root="root:shared"),
            _event("second", 1, root="root:shared"),
        ),
    )
    assert decision is None


def test_chain_rule_rejects_unknown_required_field_and_non_boolean_constraint() -> None:
    with pytest.raises(ValueError, match="required_field"):
        _rule(required_fields=("free_form_payload",))
    with pytest.raises(ValueError, match="correlation_flag"):
        _rule(same_target=1)


def test_implementation_contract_rejects_missing_chain_and_false_official_claim() -> None:
    with pytest.raises(ValueError, match="chain_missing"):
        AttackAnalyticImplementationSpec(
            "local.invalid", "T1003", "", "", ("missing.chain",), (),
            "local_artifact", "artifact_implementation", ("windows",),
            ("host_telemetry",), "", "", "candidate_only",
        )
    with pytest.raises(ValueError, match="official_fields_required"):
        AttackAnalyticImplementationSpec(
            "official.invalid", "T1003", "", "", ("anchor:api_lsass_minidump",),
            (), "exact_official", "host_telemetry", ("windows",),
            ("host_telemetry",), "", "", "candidate_only",
        )


def test_exact_official_contract_requires_bound_strategy_analytic_components_and_digest() -> None:
    spec = AttackAnalyticImplementationSpec(
        "official.valid", "T1003", "DET0001", "AN0001",
        ("anchor:api_lsass_minidump",), ("DC0001",), "exact_official",
        "host_telemetry", ("windows",), ("host_telemetry",), "a" * 64,
        "", "candidate_only",
    )
    assert spec.requirement_digest == "a" * 64
    assert spec.strategy_id == "DET0001"
    assert spec.analytic_id == "AN0001"


def test_current_bindings_are_exact_chain_references_and_honestly_non_confirmed() -> None:
    assert ATTACK_ANALYTIC_IMPLEMENTATIONS
    assert attack_analytic_implementation_manifest()["confirmed_enabled_count"] == 0
    assert all(item.support_mode != "exact_official" for item in ATTACK_ANALYTIC_IMPLEMENTATIONS)
    for mapping in ATTACK_TECHNIQUE_POLICIES:
        assert not hasattr(mapping, "chain_families")
        for implementation_id in mapping.implementation_ids:
            implementation = ATTACK_ANALYTIC_IMPLEMENTATION_BY_ID[implementation_id]
            assert implementation.technique_id == mapping.technique_id
            assert all(chain_id in CHAIN_RULE_INDEX for chain_id in implementation.chain_ids)


@pytest.mark.parametrize("chain_status", ("confirmed", "candidate", "partial"))
def test_candidate_only_implementation_never_confirms_technique(chain_status: str) -> None:
    snapshot = attack_contract_repository()
    spec = next(item for item in ATTACK_TECHNIQUE_POLICIES if item.technique_id == "T1003")
    chains = attack_chain_contract_fixture(spec, "phase6", status=chain_status, root_count=2)
    result = map_attack_evidence(snapshot, attack_mapping_evidence_fixture(TagEvidence.from_records(()), chains))
    decision = next(item for item in result.decisions if item.technique_id == "T1003")
    if chain_status == "confirmed":
        assert decision.status == "candidate"
        assert decision.rejection_reason == ""
    else:
        assert decision.status == "rejected"
        assert decision.rejection_reason == "insufficient_implementation_evidence"
        assert decision.implementation_ids == ()
    assert decision.execution_observed is False
    assert result.probability == 0.0


def test_no_family_name_only_mapping_reference_remains() -> None:
    implementation_chain_ids = {
        chain_id
        for implementation in ATTACK_ANALYTIC_IMPLEMENTATIONS
        for chain_id in implementation.chain_ids
    }
    assert implementation_chain_ids
    assert all(chain_id in CHAIN_RULE_INDEX for chain_id in implementation_chain_ids)
    assert not implementation_chain_ids.intersection({
        "credential_theft", "lateral_movement", "exfiltration",
        "fileless_loading", "bytecode_scripts", "packed_dropper",
        "defense_evasion",
    })
