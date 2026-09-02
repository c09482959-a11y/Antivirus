from __future__ import annotations

import pytest

from Virus_Scan.contracts.detection_observation import (
    DetectionObservation,
    ObservationSourceLocation,
)
from Virus_Scan.models.markov import canonical_behavior_flow


def _observation(tag: str) -> DetectionObservation:
    return DetectionObservation.create(
        tag=tag,
        producer_id="stage1477",
        stage_id="unit",
        modality="static_structure",
        artifact_identity="sha256:stage1477",
        source_location=ObservationSourceLocation("event", event_id=tag),
        evidence={"kind": "unit"},
    )


def test_stage1477_current_observations_preserve_behavior_events() -> None:
    flow = canonical_behavior_flow((_observation("api_network_download"), _observation("process_exec")))
    assert flow == ("network_download", "process_exec")


def test_stage1477_malformed_current_record_is_rejected_not_silently_reinterpreted() -> None:
    with pytest.raises((TypeError, ValueError)):
        DetectionObservation.from_value({"tag": "api_loadurl", "confidence": "nan"})


def test_stage1477_evidence_must_be_exact_bounded_builtins() -> None:
    with pytest.raises(TypeError, match="detection_observation_evidence_value_invalid"):
        DetectionObservation.create(
            tag="api_loadurl",
            producer_id="stage1477",
            stage_id="unit",
            modality="static_structure",
            artifact_identity="sha256:stage1477",
            source_location=ObservationSourceLocation("event", event_id="api_loadurl"),
            evidence=object(),
        )
