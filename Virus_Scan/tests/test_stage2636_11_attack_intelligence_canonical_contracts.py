"""Stage2636.11 canonical attack-intelligence contract regressions."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.contracts.yara_hits import YaraHit, YaraRuleIdentity
from Virus_Scan.contracts.tag_evidence import TagEvidenceRecord
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence import (
    compute_attack_intelligence,
)
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_contracts import (
    AttackClassifierRecord, AttackClassifierSpec,
)
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_policy import (
    ATTACK_ENSEMBLE_POLICY,
)
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_fusion import (
    classifier_record,
    fuse_classifier_records,
    unavailable_classifier_record,
)
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_registry import (
    ATTACK_INTELLIGENCE_CLASSIFIERS,
)
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.tags.heuristics.classifier_evidence import (
    ClassifierContribution,
    ClassifierEvidenceResult,
)
from Virus_Scan.detection.scoring.adaptive.evidence_projection_components import (
    attack_intelligence_probability_component,
    chain_probability_component,
    mitre_probability_component,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import (
    normalize_tag_evidence,
)
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import current_attack_mapping_fixture
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.tests.support.canonical_yara_fixtures import (
    canonical_test_yara_no_match_result,
    canonical_test_yara_result,
    family_alignment,
)




class _CallableDetector:
    def __call__(self, _value: object) -> ClassifierEvidenceResult:
        raise AssertionError("callable detector must never execute")

    def bound_detector(self, _value: object) -> ClassifierEvidenceResult:
        raise AssertionError("bound detector must never execute")


class _HostileValue:
    str_calls = 0
    float_calls = 0
    bool_calls = 0

    def __str__(self) -> str:
        type(self).str_calls += 1
        raise RuntimeError("hostile string hook must not execute")

    def __float__(self) -> float:
        type(self).float_calls += 1
        raise RuntimeError("hostile float hook must not execute")

    def __bool__(self) -> bool:
        type(self).bool_calls += 1
        raise RuntimeError("hostile bool hook must not execute")


def _yara_result(*, integrity_status: str = "verified"):
    return canonical_test_yara_result(verified=integrity_status == "verified")


def _reset_hooks() -> None:
    _HostileValue.str_calls = 0
    _HostileValue.float_calls = 0
    _HostileValue.bool_calls = 0


def _record(
    classifier_id: str,
    family: str,
    probability: float,
    *,
    roots: tuple[str, ...],
    groups: tuple[str, ...],
    threshold: float = 0.5,
) -> AttackClassifierRecord:
    return AttackClassifierRecord(
        classifier_id=classifier_id,
        classifier_version="test_classifier_v1",
        family=family,
        matched_root_evidence_ids=roots,
        matched_canonical_tag_ids=("test_tag",),
        matched_yara_rule_ids=(),
        direct_evidence_count=len(roots),
        inferred_evidence_count=0,
        correlation_groups=groups,
        raw_score=10.0,
        family_probability=probability,
        uncertainty=0.2,
        support=len(roots),
        ready=True,
        rejected_reasons=(),
        explanation_fields=(classifier_id + "_hit",),
        yara_state="unavailable",
        production_threshold=threshold,
    )


def _tag_record(
    tag: str,
    evidence_id: str,
    *,
    root_id: str,
    evidence_kind: str = "observed",
    parent_ids: tuple[str, ...] = (),
) -> TagEvidenceRecord:
    return TagEvidenceRecord(
        canonical_tag_id=tag,
        publication_name=tag,
        evidence_id=evidence_id,
        source_detector="stage2636_11_test",
        source_stage="attack_intelligence_contract",
        evidence_kind=evidence_kind,
        parent_evidence_ids=parent_ids,
        confidence=1.0,
        support=1.0,
        polarity="positive",
        behavior_bucket="credential_access",
        attack_phase="credential_access",
        scoreability_class="scoreable",
        correlation_group="stage2636_11_shared_group",
        root_observation_id=root_id,
        vocabulary_version="stage2636_11_test_v1",
        rule_version="stage2636_11_test_v1",
    )


def test_stage2636_11_registry_is_single_immutable_callable_owner() -> None:
    assert type(ATTACK_INTELLIGENCE_CLASSIFIERS) is tuple
    assert len(ATTACK_INTELLIGENCE_CLASSIFIERS) == 8
    assert all(type(spec) is AttackClassifierSpec for spec in ATTACK_INTELLIGENCE_CLASSIFIERS)
    assert len({spec.classifier_id for spec in ATTACK_INTELLIGENCE_CLASSIFIERS}) == 8
    assert len({spec.family for spec in ATTACK_INTELLIGENCE_CLASSIFIERS}) == 8
    assert len({spec.production_threshold for spec in ATTACK_INTELLIGENCE_CLASSIFIERS}) > 1
    with pytest.raises(FrozenInstanceError):
        ATTACK_INTELLIGENCE_CLASSIFIERS[0].family = "changed"  # type: ignore[misc]




def test_stage2636_11_classifier_contract_accepts_only_runtime_native_functions() -> None:
    spec = ATTACK_INTELLIGENCE_CLASSIFIERS[0]
    assert replace(spec, detector=spec.detector).detector is spec.detector
    callable_detector = _CallableDetector()
    with pytest.raises(TypeError, match="attack_classifier_function_required"):
        replace(spec, detector=callable_detector)
    with pytest.raises(TypeError, match="attack_classifier_function_required"):
        replace(spec, detector=callable_detector.bound_detector)


def test_stage2636_11_public_contracts_reject_hostile_values_without_hooks() -> None:
    _reset_hooks()
    spec = ATTACK_INTELLIGENCE_CLASSIFIERS[0]
    with pytest.raises(TypeError):
        AttackClassifierSpec(
            classifier_id="test",
            version="v1",
            family="test",
            detector=spec.detector,
            score_ceiling=_HostileValue(),  # type: ignore[arg-type]
            calibration_slope=1.0,
            calibration_midpoint=0.5,
            production_threshold=0.5,
        )
    with pytest.raises(TypeError):
        _record("test", "test", _HostileValue(), roots=("root",), groups=("group",))  # type: ignore[arg-type]
    assert (_HostileValue.str_calls, _HostileValue.float_calls, _HostileValue.bool_calls) == (0, 0, 0)


def test_stage2636_11_aliases_with_one_root_count_once() -> None:
    evidence = TagEvidence.from_records((
        _tag_record("lsass_access", "evidence-lsass", root_id="shared-root"),
        _tag_record("credential_dump_attempt", "evidence-dump", root_id="shared-root"),
    ))
    result = compute_attack_intelligence(evidence, ())
    credential = next(
        record for record in result["classifier_records"]
        if record["family"] == "credential_theft"
    )
    assert credential["matched_root_evidence_ids"] == ("shared-root",)
    assert credential["direct_evidence_count"] == 1
    assert credential["support"] == 1


def test_stage2636_11_inferred_only_evidence_cannot_satisfy_direct_gate() -> None:
    evidence = TagEvidence.from_records((
        _tag_record(
            "encoded_powershell",
            "derived-encoded-powershell",
            root_id="derived-root",
            evidence_kind="derived",
            parent_ids=("parent-evidence",),
        ),
    ))
    result = compute_attack_intelligence(evidence, ())
    fileless = next(
        record for record in result["classifier_records"]
        if record["family"] == "fileless_loading"
    )
    assert fileless["direct_evidence_count"] == 0
    assert fileless["inferred_evidence_count"] == 1
    assert fileless["ready"] is False
    assert fileless["family_probability"] == 0.0
    assert fileless["rejected_reasons"] == ("direct_observation_required",)


def test_stage2636_11_fusion_deduplicates_roots_and_excludes_subthreshold_records() -> None:
    strongest = _record(
        "classifier_a", "family_a", 0.8,
        roots=("shared-root",), groups=("group-a",),
    )
    correlated = _record(
        "classifier_b", "family_b", 0.7,
        roots=("shared-root",), groups=("group-b",),
    )
    subthreshold = _record(
        "classifier_c", "family_c", 0.49,
        roots=("independent-root",), groups=("group-c",),
    )
    fused = fuse_classifier_records((correlated, subthreshold, strongest))
    assert fused["aggregate_probability"] == 0.8
    assert fused["independent_classifier_ids"] == ("classifier_a",)
    assert fused["correlated_classifier_ids_rejected_from_aggregate"] == ("classifier_b",)


def test_stage2636_11_failed_classifier_does_not_corrupt_independent_record() -> None:
    failed = unavailable_classifier_record(
        ATTACK_INTELLIGENCE_CLASSIFIERS[0], "classifier_execution_failed",
    )
    valid = _record(
        "valid_classifier", "valid_family", 0.75,
        roots=("valid-root",), groups=("valid-group",),
    )
    fused = fuse_classifier_records((failed, valid))
    assert fused["aggregate_probability"] == 0.75
    assert fused["independent_classifier_ids"] == ("valid_classifier",)
    assert fused["family_probabilities"][failed.family] == 0.0


def test_stage2636_11_yara_requires_verified_identity_and_reviewed_alignment() -> None:
    tags = physical_tag_evidence(("collection", "http_upload"))
    baseline = compute_attack_intelligence(tags, canonical_test_yara_no_match_result())
    unverified_result = _yara_result(integrity_status="unverified")
    unverified = compute_attack_intelligence(tags, unverified_result)
    verified_result = _yara_result()
    correct_alignment = family_alignment(verified_result.hits[0])
    wrong_alignment = replace(correct_alignment, logic_hash="0" * 64)
    wrong_policy = compute_attack_intelligence(
        tags, verified_result, yara_family_alignments=(wrong_alignment,),
    )
    verified = compute_attack_intelligence(
        tags, verified_result, yara_family_alignments=(correct_alignment,),
    )
    family = "exfiltration"
    assert unverified["family_probabilities"][family] == baseline["family_probabilities"][family]
    assert wrong_policy["family_probabilities"][family] == baseline["family_probabilities"][family]
    assert verified["family_probabilities"][family] > baseline["family_probabilities"][family]
    assert verified["yara_state"] == "verified"
    record = next(
        item for item in verified["classifier_records"] if item["family"] == family
    )
    assert verified_result.hits[0].root_observation_id in record["matched_root_evidence_ids"]



def test_stage2636_11_valid_no_match_is_ready_negative_evidence() -> None:
    result = compute_attack_intelligence(
        normalize_tag_evidence(()), canonical_test_yara_no_match_result(),
    )
    assert result["ready"] is True
    assert result["aggregate_probability"] == 0.0
    assert result["ready_classifier_count"] == len(ATTACK_INTELLIGENCE_CLASSIFIERS)
    assert result["unavailable_classifier_count"] == 0
    assert all(record["ready"] is True for record in result["classifier_records"])


def test_stage2636_11_partial_degradation_does_not_zero_available_aggregate() -> None:
    probability, reason = attack_intelligence_probability_component(
        (), (),
        compute_attack_intelligence_fn=lambda _tags, _yara: {
            "aggregate_probability": 0.75,
            "ready": True,
            "degraded": True,
        },
    )
    assert probability == 0.75
    assert reason is None

def test_stage2636_11_attack_chain_and_mitre_projection_are_independent() -> None:
    tags = physical_tag_evidence(("lsass_access", "credential_dump_attempt"))
    chain_evidence = ChainEvidence("stage2636_11_empty_registry", "empty-digest")
    attack_probability, attack_reason = attack_intelligence_probability_component(
        tags, (), compute_attack_intelligence_fn=compute_attack_intelligence,
    )
    chain_probability, chain_reason = chain_probability_component(chain_evidence)
    mitre_probability, mitre_reason, mitre_evidence = mitre_probability_component(current_attack_mapping_fixture(tags, chain_evidence))
    assert attack_probability > 0.0 and attack_reason is None
    assert chain_probability == 0.0 and chain_reason is None
    assert mitre_probability == 0.0
    assert mitre_reason in {"mitre_not_initialized", "mitre_runtime_released", "mitre_official_mapping_unavailable"}
    assert mitre_evidence["mapping_scope"] == "official_attack_techniques"
    assert mitre_evidence["technique_ids_claimed"] is False


def test_stage2636_11_production_has_no_global_sixty_normalization_or_alias_owner() -> None:
    root = Path("Virus_Scan/detection/correlation/multi_signal")
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            root / "attack_intelligence.py",
            root / "attack_intelligence_contracts.py",
            root / "attack_intelligence_fusion.py",
            root / "attack_intelligence_registry.py",
        )
    )
    assert "/ 60" not in source
    assert "/60" not in source
    assert "_iter_attack_intelligence_classifiers" not in source
    assert "chain_probability" not in source
    assert "mitre_probability" not in source
    calibrated_midpoints = {
        spec.calibrate(spec.score_ceiling * 0.5)
        for spec in ATTACK_INTELLIGENCE_CLASSIFIERS
    }
    assert len(calibrated_midpoints) > 1
    assert ATTACK_ENSEMBLE_POLICY.evaluation_provenance


def test_stage2636_11_record_admission_rejects_forged_probability_support() -> None:
    with pytest.raises(ValueError, match="attack_classifier_probability_support_invalid"):
        AttackClassifierRecord(
            classifier_id="forged",
            classifier_version="v1",
            family="forged_family",
            matched_root_evidence_ids=(),
            matched_canonical_tag_ids=("forged_tag",),
            matched_yara_rule_ids=(),
            direct_evidence_count=0,
            inferred_evidence_count=0,
            correlation_groups=(),
            raw_score=10.0,
            family_probability=0.9,
            uncertainty=0.1,
            support=0,
            ready=True,
            rejected_reasons=(),
            explanation_fields=("forged",),
            yara_state="unavailable",
            production_threshold=0.5,
        )


def test_stage2636_11_fusion_rejects_duplicate_classifier_owners() -> None:
    first = _record(
        "duplicate", "family_a", 0.8, roots=("root-a",), groups=("group-a",),
    )
    second = _record(
        "duplicate", "family_b", 0.7, roots=("root-b",), groups=("group-b",),
    )
    with pytest.raises(ValueError, match="attack_classifier_record_id_duplicate"):
        fuse_classifier_records((first, second))


def test_stage2636_11_classifier_rejects_unmatched_root_attribution() -> None:
    evidence = TagEvidence.from_records((
        _tag_record("lsass_access", "real-evidence", root_id="real-root"),
    ))
    result = ClassifierEvidenceResult((
        ClassifierContribution(("real-root",), 5.0, "real contribution"),
        ClassifierContribution(("ghost-root",), 100.0, "ghost contribution"),
    ))
    spec = next(
        item for item in ATTACK_INTELLIGENCE_CLASSIFIERS
        if item.family == "credential_theft"
    )
    record = classifier_record(
        spec, result, evidence, (), yara_family_alignments=(),
    )
    assert record.matched_root_evidence_ids == ("real-root",)
    assert record.support == 1
    assert record.ready is False
    assert record.family_probability == 0.0
    assert record.rejected_reasons == ("classifier_root_attribution_invalid",)
    assert "ghost contribution" not in record.explanation_fields


def test_stage2636_11_yara_contract_rejects_forged_verified_provenance() -> None:
    with pytest.raises(ValueError, match="partial_yara_rule_provenance_rejected"):
        YaraRuleIdentity(
            package_kind="custom",
            rule_source_digest="a" * 64,
            compiled_cache_digest="",
            rule_catalog_digest="",
            source_member="rules/test.yar",
            compiler_namespace="ns_test",
            rule_name="forged_rule",
        )


def test_stage2636_11_physical_yara_hit_rejects_semantic_fields() -> None:
    result = canonical_test_yara_result()
    hit = result.hits[0]
    with pytest.raises(TypeError):
        YaraHit(
            rule_identity=hit.rule_identity,
            root_observation_id=hit.root_observation_id,
            integrity_status=hit.integrity_status,
            source_trust=hit.source_trust,
            release_id=hit.release_id,
            release_tag=hit.release_tag,
            compile_policy_version=hit.compile_policy_version,
            artifact_identity=hit.artifact_identity,
            source_location=hit.source_location,
            mapped_families=("exfiltration",),  # type: ignore[call-arg]
        )

