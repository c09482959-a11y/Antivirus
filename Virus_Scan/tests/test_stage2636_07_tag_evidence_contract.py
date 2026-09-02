from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from Virus_Scan.contracts.detection_observation import (
    DetectionObservation,
    ObservationSourceLocation,
    artifact_observations_for_tags,
)
from Virus_Scan.contracts.tag_evidence import (
    TagEvidenceRecord,
    deterministic_tag_evidence_id,
    distinct_positive_root_ids_for_tags,
    positive_tag_group_root_matches,
    positive_tag_groups_have_distinct_roots,
    tag_evidence_record_from_mapping,
)
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.registries.tag_behavior.vocabulary_graph import (
    MAX_TAG_DERIVATION_OUTPUTS,
    TAG_DERIVATION_RULES,
    TagDerivationRule,
    validate_tag_derivation_rules,
)
from Virus_Scan.detection.scoring.weighting.scoreable_tags import (
    concrete_score_count,
    required_scoreable_tags_have_distinct_roots,
    scoreable_tag_evidence,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence

_ALL_MODEL_KINDS = frozenset({"observed", "normalized", "derived", "composite"})


def _observation(tag: str, event_id: str) -> DetectionObservation:
    return DetectionObservation.create(
        tag=tag,
        producer_id="test",
        stage_id="observation",
        modality="static_structure",
        artifact_identity="sha256:test",
        source_location=ObservationSourceLocation("event", event_id=event_id),
        integrity_status="verified",
    )


def _observed_record(tag: str, root: str = "root-1") -> TagEvidenceRecord:
    return normalize_tag_evidence((_observation(tag, root),), derive=False).records[0]


def _same_root_bundle(*tags: str):
    observations = artifact_observations_for_tags(
        tags,
        producer_id="test",
        stage_id="observation",
        artifact_identity="sha256:test",
        source_location=ObservationSourceLocation("event", event_id="shared"),
        modality="static_structure",
        integrity_status="verified",
    )
    return normalize_tag_evidence(observations)


def _separate_root_bundle(*tags: str):
    return normalize_tag_evidence(tuple(
        _observation(tag, "event-" + int.__str__((index)) + "-" + tag)
        for index, tag in enumerate(tags)
    ))


def test_stage2636_07_alias_normalization_preserves_one_root_and_kind_lineage() -> None:
    bundle = _same_root_bundle("schtasks", "scheduled_task")

    assert bundle.tags == ("schtasks_create", "schtasks")
    assert bundle.summary["raw_observation_count"] == 1
    assert [record.evidence_kind for record in bundle.records] == [
        "observed", "normalized", "derived",
    ]
    assert len({record.root_observation_id for record in bundle.records}) == 1
    assert bundle.records[0].raw_observation_name == "schtasks"
    assert bundle.records[1].parent_evidence_ids == (bundle.records[0].evidence_id,)


def test_stage2636_07_alias_derived_tags_cannot_satisfy_distinct_signal_gate() -> None:
    one_root = _same_root_bundle("cmd_exec")
    separate_roots = _separate_root_bundle("cmd_exec", "powershell_exec")

    assert required_scoreable_tags_have_distinct_roots(
        one_root,
        frozenset({"cmd_exec", "powershell_exec"}),
        allowed_evidence_kinds=_ALL_MODEL_KINDS,
    ) is False
    assert required_scoreable_tags_have_distinct_roots(
        separate_roots,
        frozenset({"cmd_exec", "powershell_exec"}),
        allowed_evidence_kinds=_ALL_MODEL_KINDS,
    ) is True
    assert concrete_score_count(one_root) == 1
    assert concrete_score_count(separate_roots) == 2


def test_stage2636_07_graph_rejects_cycles_unknowns_and_conflicts() -> None:
    declared = frozenset({"a", "b", "c"})
    with pytest.raises(ValueError, match="cyclic"):
        validate_tag_derivation_rules(
            (TagDerivationRule("a", "b"), TagDerivationRule("b", "a")),
            declared_tags=declared,
        )
    with pytest.raises(ValueError, match="unknown"):
        validate_tag_derivation_rules(
            (TagDerivationRule("a", "missing"),),
            declared_tags=declared,
        )
    with pytest.raises(ValueError, match="conflicting"):
        validate_tag_derivation_rules(
            (
                TagDerivationRule("a", "b", rule_id="first"),
                TagDerivationRule("a", "b", polarity="neutral", rule_id="second"),
            ),
            declared_tags=declared,
        )


def test_stage2636_07_records_are_frozen_replayable_and_bounded() -> None:
    original = _same_root_bundle("powershell_encoded").records[0]
    replayed = tag_evidence_record_from_mapping(original.to_record())

    assert replayed == original
    with pytest.raises(FrozenInstanceError):
        original.canonical_tag_id = "changed"  # type: ignore[misc]

    all_sources = tuple(rule.source_tag for rule in TAG_DERIVATION_RULES)
    bounded = _same_root_bundle(*all_sources)
    assert len(bounded.records) <= MAX_TAG_DERIVATION_OUTPUTS
    assert tuple(bounded.tags) == tuple(dict.fromkeys(bounded.tags))


def test_stage2636_07_suppression_is_negative_and_never_scoreable() -> None:
    observed = _observed_record("cmd_exec")
    suppression = TagEvidenceRecord(
        canonical_tag_id="cmd_exec",
        publication_name="cmd_exec",
        evidence_id="",
        source_detector="test_policy",
        source_stage="suppression",
        evidence_kind="suppression",
        parent_evidence_ids=(observed.evidence_id,),
        confidence=1.0,
        support=1.0,
        polarity="negative",
        scoreability_class="suppressed",
        correlation_group=observed.correlation_group,
        root_observation_id=observed.root_observation_id,
        unavailable_reason="suppressed_for_test",
    )
    bundle = TagEvidence.from_records((observed, suppression))
    scored = scoreable_tag_evidence(bundle, allowed_evidence_kinds=_ALL_MODEL_KINDS)

    assert bundle.tags == ()
    assert scored.tags == ()
    assert concrete_score_count(bundle) == 0


def test_stage2636_07_hostile_objects_do_not_execute_hooks() -> None:
    calls: list[str] = []

    class Hostile:
        def __iter__(self):
            calls.append("iter")
            raise AssertionError("caller hook executed")

        def __str__(self):
            calls.append("str")
            raise AssertionError("caller hook executed")

        def __bool__(self):
            calls.append("bool")
            raise AssertionError("caller hook executed")

    bundle = normalize_tag_evidence(Hostile())

    assert calls == []
    assert bundle.summary["failure_count"] >= 1
    assert concrete_score_count(bundle) == 0


def test_stage2636_07_semantic_groups_require_distinct_roots() -> None:
    groups = (frozenset({"cmd_exec"}), frozenset({"encoded_powershell"}))
    one_root = _same_root_bundle("cmd_exec")
    separate_roots = _separate_root_bundle("cmd_exec", "encoded_powershell")

    assert positive_tag_group_root_matches(
        one_root.records, groups, allowed_evidence_kinds=_ALL_MODEL_KINDS,
    ) == ((one_root.records[0].root_observation_id, "cmd_exec"),)
    assert positive_tag_groups_have_distinct_roots(
        one_root.records, groups, allowed_evidence_kinds=_ALL_MODEL_KINDS,
    ) is False
    assert positive_tag_groups_have_distinct_roots(
        separate_roots.records, groups, allowed_evidence_kinds=_ALL_MODEL_KINDS,
    ) is True


def test_stage2636_07_archive_inner_projection_preserves_one_root() -> None:
    bundle = _same_root_bundle("archive_inner:shadowcopy_delete")

    assert "archive_inner:shadowcopy_delete" in bundle.tags
    assert "shadowcopy_delete" in bundle.tags
    assert len({record.root_observation_id for record in bundle.records}) == 1
    projected = next(record for record in bundle.records if record.canonical_tag_id == "shadowcopy_delete")
    assert projected.evidence_kind == "derived"
    assert projected.parent_evidence_ids == (bundle.records[0].evidence_id,)


def test_stage2636_07_tag_root_count_ignores_alias_cardinality() -> None:
    one_root = _same_root_bundle("cmd_exec")
    two_roots = _separate_root_bundle("cmd_exec", "encoded_powershell")
    candidates = ("cmd_exec", "powershell_exec", "encoded_powershell")

    assert len(distinct_positive_root_ids_for_tags(
        one_root.records, candidates, allowed_evidence_kinds=_ALL_MODEL_KINDS,
    )) == 1
    assert len(distinct_positive_root_ids_for_tags(
        two_roots.records, candidates, allowed_evidence_kinds=_ALL_MODEL_KINDS,
    )) == 2
