import ast

import pytest

from Virus_Scan.contracts import DetectionObservation
from Virus_Scan.contracts.detection_observation import DetectionObservation as DirectObservation, ObservationSourceLocation
from Virus_Scan.contracts.schema_registry import register_schema, schema_snapshot
from Virus_Scan.contracts.string_eval import const_eval_string_node


def _expr(src: str):
    return ast.parse(src, mode="eval").body


def test_stage955_detection_observation_current_record_preserves_physical_identity_and_evidence():
    raw = DetectionObservation.create(
        tag="process-injection",
        producer_id="scanner",
        stage_id="binary",
        modality="static_structure",
        platform="windows",
        artifact_identity="sha256:abc",
        source_location=ObservationSourceLocation(
            "file_offset", locator="game/script.rpyc", byte_offset=12,
        ),
        confidence=0.75,
        evidence={"nested": {"kind": "pickle"}},
    ).to_record()

    observation = DetectionObservation.from_value(raw)

    assert DetectionObservation is DirectObservation
    assert observation.tag == "process-injection"
    assert observation.confidence == 0.75
    assert observation.producer_id == "scanner"
    assert observation.stage_id == "binary"
    assert observation.artifact_identity == "sha256:abc"
    assert observation.source_location.byte_offset == 12
    assert observation.evidence["nested"]["kind"] == "pickle"
    with pytest.raises(TypeError):
        observation.evidence["nested"] = "other"


def test_stage955_detection_observation_existing_identity_and_flat_string_rejection():
    existing = DetectionObservation.create(
        tag="network-download",
        producer_id="unit",
        stage_id="test",
        modality="static_string",
        artifact_identity="sha256:def",
        source_location=ObservationSourceLocation("file_offset", locator="sample", byte_offset=4),
        confidence=0.5,
        evidence={"url": "https://example.invalid"},
    )

    assert DetectionObservation.from_value(existing) is existing

    with pytest.raises(TypeError, match="detection_observation_record_invalid"):
        DetectionObservation.from_value("Credential-Access")


def test_stage955_string_eval_accepts_only_static_string_composition():
    env = {"ROOT": "game", "EXT": ".rpy"}

    assert const_eval_string_node(_expr('"game/" + "script" + EXT'), env) == "game/script.rpy"
    assert const_eval_string_node(_expr('f"static/path"'), env) == "static/path"
    assert const_eval_string_node(_expr('"game/script.rpyc".replace(".rpyc", ".rpy")'), env) == "game/script.rpy"
    assert const_eval_string_node(_expr('"prefix/" + ROOT'), env) == "prefix/game"


def test_stage955_string_eval_rejects_dynamic_or_non_string_expressions():
    assert const_eval_string_node(_expr('f"dynamic-{value}"'), {"value": "x"}) is None
    assert const_eval_string_node(_expr('"x".format()')) is None
    assert const_eval_string_node(_expr('1 + 2')) is None
    assert const_eval_string_node(_expr('"x" + missing_name'), {}) is None


def test_stage955_schema_registry_rejects_owner_version_and_validator_drift_without_mutating_snapshot():
    before = schema_snapshot()

    with pytest.raises(RuntimeError, match="schema registration drift"):
        register_schema("result_record", owner="contracts.result_record", version=2)

    with pytest.raises(RuntimeError, match="schema registration drift"):
        register_schema("result_record", owner="contracts.other", version=1)

    with pytest.raises(RuntimeError, match="schema validator drift"):
        register_schema("result_record", owner="contracts.result_record", version=1, validator=lambda value: True)

    assert schema_snapshot() == before
