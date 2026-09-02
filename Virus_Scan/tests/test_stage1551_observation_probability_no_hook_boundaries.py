from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.contracts.detection_observation import DetectionObservation, ObservationSourceLocation
from Virus_Scan.contracts.probabilistic_evidence import correlation_group_summary, probabilistic_evidence_summary
from Virus_Scan.models.markov import canonical_behavior_flow


class HostileMapping(Mapping):
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate caller mapping")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("do not len caller mapping")

    def __getitem__(self, key):
        type(self).touched += 1
        raise RuntimeError("do not index caller mapping")

    def get(self, key, default=None):
        type(self).touched += 1
        raise RuntimeError("do not get caller mapping")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("do not items caller mapping")


class HostileIterable:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate caller iterable")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test caller iterable")


class HostileText:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify caller object")


class PlainTextField:
    touched = 0

    def __init__(self, text: str) -> None:
        self._text = text

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify caller text field object")


def test_detection_observation_rejects_unknown_mapping_without_mapping_hooks() -> None:
    HostileMapping.touched = 0
    try:
        DetectionObservation.from_value(HostileMapping())
    except TypeError:
        pass
    else:  # pragma: no cover
        raise AssertionError("custom mapping crossed exact-current observation boundary")

    assert HostileMapping.touched == 0
    assert canonical_behavior_flow(HostileMapping()) == ()
    assert HostileMapping.touched == 0


def test_detection_observation_direct_evidence_rejects_unknown_mapping_without_hooks() -> None:
    HostileMapping.touched = 0
    try:
        DetectionObservation.create(
            tag="api_loadurl",
            producer_id="unit",
            stage_id="unit",
            modality="static_structure",
            artifact_identity="sha256:unit",
            source_location=ObservationSourceLocation("event", event_id="api_loadurl"),
            evidence=HostileMapping(),
        )
    except TypeError:
        pass
    else:  # pragma: no cover
        raise AssertionError("hostile mapping evidence was accepted")
    assert HostileMapping.touched == 0


def test_probabilistic_evidence_rejects_unknown_iterable_without_iterating() -> None:
    HostileIterable.touched = 0
    groups = correlation_group_summary(HostileIterable())
    summary = probabilistic_evidence_summary(HostileIterable())

    assert HostileIterable.touched == 0
    assert groups["unsupported_probability_evidence"]["invalid_numeric_reason"] == "unsupported_probability_evidence_iterable"
    assert summary["degraded"] is True
    assert summary["reason"] == "no_valid_probability_evidence"


def test_canonical_chain_evaluator_rejects_unknown_text_without_str_hook() -> None:
    HostileText.touched = 0

    evidence = evaluate_chain_evidence(tags=(HostileText(),))
    assert evidence.decisions == ()
    assert evidence.failures
    assert HostileText.touched == 0


def test_non_builtin_text_field_is_rejected_without_str_hook() -> None:
    PlainTextField.touched = 0
    try:
        DetectionObservation.from_value({"tag": PlainTextField("api_loadurl")})
    except (TypeError, ValueError):
        pass
    else:  # pragma: no cover
        raise AssertionError("caller-owned text field was accepted")
    assert PlainTextField.touched == 0
