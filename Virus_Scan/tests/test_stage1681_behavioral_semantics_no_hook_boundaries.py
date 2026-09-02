from Virus_Scan.detection.evidence.behavioral.probabilistic_semantics import (
    probabilistic_evidence_semantics,
)
from Virus_Scan.detection.evidence.behavioral.semantics import (
    semantic_evidence_vector_overlay,
    tag_effective_evidence_score,
    tag_evidence_provenance_report,
)


class HostileText:
    touched = 0

    def __bool__(self):
        HostileText.touched += 1
        raise RuntimeError("do not truth-test")

    def __str__(self):
        HostileText.touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        HostileText.touched += 1
        raise RuntimeError("do not repr")


class HostileNumber:
    touched = 0

    def __bool__(self):
        HostileNumber.touched += 1
        raise RuntimeError("do not truth-test")

    def __float__(self):
        HostileNumber.touched += 1
        raise RuntimeError("do not float")

    def __int__(self):
        HostileNumber.touched += 1
        raise RuntimeError("do not int")


class HostileIterable:
    touched = 0

    def __bool__(self):
        HostileIterable.touched += 1
        raise RuntimeError("do not truth-test")

    def __iter__(self):
        HostileIterable.touched += 1
        raise RuntimeError("do not iterate")


class HostileMappingLike:
    touched = 0

    def __bool__(self):
        HostileMappingLike.touched += 1
        raise RuntimeError("do not truth-test")

    def __iter__(self):
        HostileMappingLike.touched += 1
        raise RuntimeError("do not iterate")

    def items(self):
        HostileMappingLike.touched += 1
        raise RuntimeError("do not call items")

    def get(self, key, default=None):
        HostileMappingLike.touched += 1
        raise RuntimeError("do not call get")


class HostileYaraRule:
    touched = 0

    @property
    def rule(self):
        HostileYaraRule.touched += 1
        raise RuntimeError("do not access rule")

    def __str__(self):
        HostileYaraRule.touched += 1
        raise RuntimeError("do not stringify")


def test_stage1681_probabilistic_semantics_rejects_hostile_labels_and_numbers_without_hooks():
    HostileText.touched = 0
    HostileNumber.touched = 0

    result = probabilistic_evidence_semantics(
        evidence_type=HostileText(),
        reliability=HostileText(),
        strength=HostileText(),
        correlation_group=HostileText(),
        raw_confidence=HostileNumber(),
        likelihood=HostileNumber(),
        prior=HostileNumber(),
        prevalence=HostileNumber(),
    )

    assert HostileText.touched == 0
    assert HostileNumber.touched == 0
    assert result["failure_evidence_recorded"] is True
    assert result["degraded"] is True
    assert "unsafe_probabilistic_reliability_label_rejected" in result["input_rejections"]
    assert "unsafe_probabilistic_raw_confidence_rejected" in result["input_rejections"]
    assert result["posterior"] == 0.0


def test_stage1681_tag_effective_evidence_score_rejects_hostile_tag_without_stringifying():
    HostileText.touched = 0

    result = tag_effective_evidence_score("renpy", "sample.rpy", HostileText())

    assert HostileText.touched == 0
    assert result["ready"] is False
    assert result["reason"] == "unsafe_behavior_tag_rejected"
    assert result["failure_evidence_recorded"] is True


def test_stage1681_tag_provenance_rejects_hostile_sequences_and_yara_rules_without_hooks():
    HostileIterable.touched = 0
    HostileYaraRule.touched = 0

    result = tag_evidence_provenance_report(
        tags=HostileIterable(),
        api_calls=HostileIterable(),
        ordered_events=HostileIterable(),
    )

    assert HostileIterable.touched == 0
    assert HostileYaraRule.touched == 0
    assert result["records"] == []
    assert result["failure_evidence_recorded"] is True
    assert "behavior_tags_sequence_rejected" in result["input_rejections"]


def test_stage1681_semantic_vector_rejects_hostile_boundaries_without_hooks():
    HostileIterable.touched = 0
    HostileMappingLike.touched = 0
    HostileNumber.touched = 0

    result = semantic_evidence_vector_overlay(
        tags=HostileIterable(),
        yara_hits=HostileIterable(),
        oddity=HostileMappingLike(),
        markov=HostileMappingLike(),
        graph=HostileMappingLike(),
        risk=HostileNumber(),
    )

    assert HostileIterable.touched == 0
    assert HostileMappingLike.touched == 0
    assert HostileNumber.touched == 0
    assert result["failure_evidence_recorded"] is True
    assert result["vector"]["risk"] == 0.0
    assert "semantic_vector_tags_sequence_rejected" in result["input_rejections"]
    assert "behavior_yara_hits_rejected" in result["input_rejections"]
    assert "semantic_oddity_mapping_rejected" in result["input_rejections"]
    assert "unsafe_semantic_vector_risk_rejected" in result["input_rejections"]


def test_stage1681_semantics_preserves_valid_primitive_behavior():
    report = tag_evidence_provenance_report(
        tags=("network_download",),
        api_calls=("urlmon urldownloadtofile",),
        ordered_events=("network_download",),
    )
    vector = semantic_evidence_vector_overlay(
        tags=("network_download", "credential_dump_attempt"),
        yara_hits=("CredentialRule",),
        oddity={"confidence": 0.2},
        markov={"confidence": 0.3},
        graph={"confidence": 0.4},
        risk=50.0,
    )

    assert report["records"]
    assert report["records"][0]["tag"] == "network_download"
    assert "input_rejections" not in report
    assert vector["vector"]["network_bucket"] == 1.0
    assert vector["vector"]["credential_bucket"] == 1.0
    assert vector["vector"]["risk"] == 0.5
    assert vector["vector"]["yara_confidence"] == 0.0
    assert vector["yara_context"]["probability_authority"] is False
    assert "input_rejections" not in vector
