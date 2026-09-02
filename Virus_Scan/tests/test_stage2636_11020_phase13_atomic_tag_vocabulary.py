from __future__ import annotations

from Virus_Scan.contracts.detection_observation import (
    DetectionObservation,
    ObservationSourceLocation,
)
from Virus_Scan.contracts.tag_evidence import TagEvidenceRecord
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence import (
    compute_attack_intelligence,
)
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_contracts import (
    ATTACK_INTELLIGENCE_EVIDENCE_VERSION,
)
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_registry import (
    ATTACK_INTELLIGENCE_CLASSIFIER_REGISTRY_DIGEST,
    ATTACK_INTELLIGENCE_CLASSIFIER_REGISTRY_MANIFEST,
    ATTACK_INTELLIGENCE_CLASSIFIER_REGISTRY_VERSION,
    attack_intelligence_classifier_registry_manifest,
)
from Virus_Scan.contracts.static_program_analysis import (
    STATIC_OPERATION_KINDS,
    StaticObservationReference,
    static_operation_observation_tag,
)
from Virus_Scan.contracts.tag_taxonomy import (
    TAG_CLASS_ATOMIC_OBSERVATION,
    TAG_CLASS_BEHAVIOR_DERIVATION,
)
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.registries.chain_gate_registry_defaults import (
    CONCRETE_SCORE_TAGS,
    HIGH_CONFIDENCE_ATTACK_ANCHOR_TAGS,
    HIGH_GATE_SINGLE_ANCHOR_TAGS,
    MAJOR_ATTACK_ANCHOR_TAGS,
    SINGLE_ANCHOR_SCORE_CHAINS,
    TAG_BEHAVIOR_SCOREABLE,
)
from Virus_Scan.detection.registries.tag_taxonomy_registry import tag_class_for
from Virus_Scan.detection.scoring.weighting.scoreable_tags import scoreable_tag_set
from Virus_Scan.detection.scoring.weighting.tag_audit import (
    audit_tag_can_score,
    audit_tag_class,
)
from Virus_Scan.detection.tags.heuristics.behavior_derivation import (
    derive_behavior_evidence,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import (
    canonical_tag_name,
    normalize_tag_evidence,
)

_BROAD_CONTEXT_TAGS = frozenset({
    "backdoor_or_c2",
    "credential_access",
    "dropper_behavior",
    "fileless_execution",
    "high_confidence_browser_credential_theft",
    "high_confidence_credential_theft",
    "in_memory_execution",
    "network_exfiltration",
    "payload_decode",
    "payload_execution",
    "process_exec",
    "process_injection",
    "script_execution",
    "shellcode_exec",
    "token_exfiltration",
})


def _observation(
    tag: str,
    event_id: str,
    *,
    modality: str = "static_string",
    evidence: dict[str, object] | None = None,
) -> DetectionObservation:
    return DetectionObservation.create(
        tag=tag,
        producer_id="phase13_test",
        stage_id="tag_authority",
        modality=modality,
        artifact_identity="sha256:phase13",
        source_location=ObservationSourceLocation("event", event_id=event_id),
        integrity_status="verified",
        directness="direct",
        confidence=1.0,
        evidence={} if evidence is None else evidence,
    )


def test_phase13_static_operation_vocabulary_is_explicitly_atomic() -> None:
    tags = tuple(sorted(static_operation_observation_tag(kind) for kind in STATIC_OPERATION_KINDS))

    assert tags
    assert all(tag_class_for(tag) == TAG_CLASS_ATOMIC_OBSERVATION for tag in tags)


def test_phase13_direct_broad_scanner_tags_are_preserved_as_context_only() -> None:
    for index, tag in enumerate(sorted(_BROAD_CONTEXT_TAGS)):
        bundle = normalize_tag_evidence((_observation(tag, f"broad-{index}"),), derive=False)
        canonical = canonical_tag_name(tag)
        observed = next(record for record in bundle.records if record.evidence_kind == "observed")

        assert canonical in bundle.tags
        assert tag_class_for(tag) == TAG_CLASS_BEHAVIOR_DERIVATION
        assert observed.raw_observation_name == tag
        assert observed.directness == "context"
        assert any(record.scoreability_class == "support" for record in bundle.records)
        assert all(record.directness == "context" for record in bundle.records)
        assert audit_tag_can_score(tag, {tag}) is False
        assert canonical not in scoreable_tag_set(bundle)


def test_phase13_atomic_observation_remains_direct_and_scoreable_when_registered() -> None:
    bundle = normalize_tag_evidence((_observation("powershell_exec", "atomic", modality="static_structure"),), derive=False)
    record = bundle.records[0]

    assert tag_class_for("powershell_exec") == TAG_CLASS_ATOMIC_OBSERVATION
    assert record.scoreability_class == "scoreable"
    assert record.directness == "direct"
    assert record.correlation_group == "powershell_exec"
    assert audit_tag_class("powershell_exec") == "behavior"
    assert audit_tag_can_score("powershell_exec", {"powershell_exec"}) is True
    assert scoreable_tag_set(bundle) == {"powershell_exec"}


def test_phase13_static_flow_identity_is_the_exact_correlation_owner() -> None:
    flow_identity = "flow_" + "a" * 32
    operation_id = "sop_" + "b" * 40
    actor_identity = "spe_phase13"
    target_identity = "res_phase13_target"
    reference = StaticObservationReference(
        analysis_semantic_digest="c" * 64,
        operation_id=operation_id,
        actor_program_entity=actor_identity,
        enclosing_function_id="fn_phase13",
        basic_block_id="bb_phase13",
        target_resource_identity=target_identity,
        flow_identity=flow_identity,
    )
    observation = DetectionObservation.create(
        tag="static_network_send_operation",
        producer_id="phase13_test",
        stage_id="tag_authority",
        modality="static_control_flow",
        actor_identity=actor_identity,
        target_identity=target_identity,
        artifact_identity="content_sha256:" + "d" * 64,
        source_location=ObservationSourceLocation(
            "static_operation",
            locator="phase13.py",
            event_id=operation_id,
        ),
        integrity_status="verified",
        directness="direct",
        confidence=1.0,
        evidence={
            "claim_scope": "static_operation",
            "execution_observed": False,
            "static_observation_reference": reference.to_record(),
        },
    )
    record = normalize_tag_evidence((observation,), derive=False).records[0]

    assert record.directness == "direct"
    assert record.scoreability_class == "support"
    assert record.correlation_group == flow_identity
    assert record.root_observation_id == observation.root_observation_id


def test_phase13_behavior_derivation_accepts_only_atomic_direct_parents() -> None:
    broad = normalize_tag_evidence((_observation("credential_access", "broad"),), derive=False)
    broad_derived = TagEvidence.from_records(derive_behavior_evidence(broad.records))
    atomic = normalize_tag_evidence((_observation("dpapi_access", "atomic", modality="static_structure"),), derive=False)
    atomic_derived = TagEvidence.from_records(derive_behavior_evidence(atomic.records))

    assert tuple(record.canonical_tag_id for record in broad_derived.records) == ("credential_access",)
    derived = next(
        record for record in atomic_derived.records
        if record.canonical_tag_id == "credential_access" and record.evidence_kind == "derived"
    )
    assert derived.parent_evidence_ids == (atomic.records[0].evidence_id,)
    assert derived.root_observation_id == atomic.records[0].root_observation_id
    assert derived.directness == "derived"
    assert derived.scoreability_class == "support"


def test_phase13_score_and_high_gate_registries_contain_only_atomic_tags() -> None:
    registries = (
        CONCRETE_SCORE_TAGS,
        TAG_BEHAVIOR_SCOREABLE,
        HIGH_CONFIDENCE_ATTACK_ANCHOR_TAGS,
        HIGH_GATE_SINGLE_ANCHOR_TAGS,
        MAJOR_ATTACK_ANCHOR_TAGS,
        SINGLE_ANCHOR_SCORE_CHAINS,
    )

    assert all(
        tag_class_for(tag) == TAG_CLASS_ATOMIC_OBSERVATION
        for registry in registries
        for tag in registry
    )


def _classifier_record(
    tag: str,
    *,
    root_id: str,
    evidence_kind: str = "observed",
    directness: str = "direct",
) -> object:
    return TagEvidenceRecord(
        canonical_tag_id=tag,
        publication_name=tag,
        evidence_id="tag_ev_" + root_id.removeprefix("obs_")[:32],
        source_detector="phase13_classifier_test",
        source_stage="classifier_authority",
        evidence_kind=evidence_kind,
        confidence=1.0,
        support=1.0,
        polarity="positive",
        behavior_bucket="other_behavior",
        attack_phase="unknown",
        scoreability_class="scoreable",
        correlation_group=tag,
        root_observation_id=root_id,
        vocabulary_version="phase13_classifier_v1",
        rule_version="phase13_classifier_v1",
        observation_id=root_id,
        modality="static_structure",
        artifact_identity="sha256:phase13-classifier",
        source_location=ObservationSourceLocation(
            "fixture_event", locator="phase13", event_id=root_id,
        ),
        integrity_status="verified",
        directness=directness,
    )


def test_phase13_attack_classifiers_reject_broad_context_authority() -> None:
    broad = TagEvidence.from_records((
        _classifier_record("script_execution", root_id="obs_" + "1" * 40),
        _classifier_record("process_exec", root_id="obs_" + "2" * 40),
        _classifier_record("credential_access", root_id="obs_" + "3" * 40),
        _classifier_record("network_exfiltration", root_id="obs_" + "4" * 40),
    ))
    result = compute_attack_intelligence(broad, ())

    assert result["aggregate_probability"] == 0.0
    assert result["independent_classifier_ids"] == ()
    assert all(
        record["matched_root_evidence_ids"] == ()
        for record in result["classifier_records"]
    )


def test_phase13_attack_classifier_never_double_counts_overlapping_roots() -> None:
    root_allocate = "obs_" + "a" * 40
    root_write = "obs_" + "b" * 40
    root_execute = "obs_" + "c" * 40
    evidence = TagEvidence.from_records((
        _classifier_record("memory_allocate", root_id=root_allocate),
        _classifier_record("memory_write", root_id=root_write),
        _classifier_record("thread_execution", root_id=root_execute),
        _classifier_record("powershell_exec", root_id=root_execute),
    ))
    result = compute_attack_intelligence(evidence, ())
    fileless = next(
        record for record in result["classifier_records"]
        if record["family"] == "fileless_loading"
    )

    assert fileless["raw_score"] == 18.0
    assert fileless["matched_root_evidence_ids"] == tuple(sorted((
        root_allocate,
        root_execute,
        root_write,
    )))
    assert fileless["explanation_fields"] == ("memory-only payload execution",)


def test_phase13_classifier_registry_identity_is_current_and_deterministic() -> None:
    assert ATTACK_INTELLIGENCE_EVIDENCE_VERSION == "attack_intelligence_evidence_v3"
    assert ATTACK_INTELLIGENCE_CLASSIFIER_REGISTRY_VERSION == "attack_classifier_registry_v3"
    assert len(ATTACK_INTELLIGENCE_CLASSIFIER_REGISTRY_DIGEST) == 64
    assert attack_intelligence_classifier_registry_manifest() == (
        ATTACK_INTELLIGENCE_CLASSIFIER_REGISTRY_MANIFEST
    )
    assert all(
        record["version"] == "attack_classifier_v3"
        for record in ATTACK_INTELLIGENCE_CLASSIFIER_REGISTRY_MANIFEST["records"]
    )
