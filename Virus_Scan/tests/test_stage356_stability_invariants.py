from __future__ import annotations

import pytest

from Virus_Scan.contracts.result_record import (
    EvidenceObjectSnapshot,
    validate_evidence_object_invariants,
    validate_result_record_invariants,
)
from Virus_Scan.routing.context_identity import EngineContextIdentity


def _route(**changes):
    data = dict(
        container_engine="unity",
        container_engine_confidence=1.0,
        artifact_engine="unity",
        artifact_engine_confidence=1.0,
        declared_extension=".dll",
        sniffed_type="pe",
        sniffed_embedded_types=("pe",),
        extension_mismatch=False,
        cross_engine_artifact=False,
        engine_mismatch=False,
        effective_analysis_engine="unity_dotnet",
        baseline_key="unity/.dll",
        extension_baseline="unity/.dll",
        contextual_baseline="unity::.dll",
        container_extension_baseline="unity/.dll",
        secondary_baseline_keys=("unity/.dll",),
        baseline_lookup_order=("unity/.dll", "unity::.dll"),
        learning_baseline_key="unity/.dll",
        blocked_baseline_keys=(),
        learning_allowed=True,
        learning_reason="trusted_benign",
        fingerprint_evidence=("unity:managed_dll",),
    )
    data.update(changes)
    return EngineContextIdentity(**data)


def test_stage356_evidence_snapshot_rejects_non_json_evidence_objects() -> None:
    with pytest.raises(ValueError, match="non-json value"):
        EvidenceObjectSnapshot.from_value("decoded_evidence_snippets", [{"raw": object()}], context="stage356")


def test_stage356_high_risk_result_rejects_malformed_evidence_even_when_tags_exist() -> None:
    record = {
        "file": "sample.bin",
        "path": "sample.bin",
        "verdict": "malicious",
        "score": 95,
        "tags": ["encoded_payload"],
        "decoded_evidence_snippets": [{"payload": object()}],
    }
    with pytest.raises(ValueError, match="non-json value"):
        validate_result_record_invariants(record, context="stage356_result")


def test_stage356_result_accepts_explicit_json_evidence_shape() -> None:
    record = {
        "file": "sample.bin",
        "path": "sample.bin",
        "verdict": "malicious",
        "score": 95,
        "tags": ["encoded_payload"],
        "decoded_evidence_snippets": [{"payload": "powershell -enc AAAA", "depth": 1}],
        "engine_routing_evidence": ["unity/.dll"],
    }
    assert validate_evidence_object_invariants(record, context="stage356_result") is True
    assert validate_result_record_invariants(record, context="stage356_result") is True


def test_stage356_engine_route_rejects_invalid_confidence() -> None:
    with pytest.raises(ValueError, match="invalid artifact_engine_confidence"):
        _route(artifact_engine_confidence=1.25).validate(context="stage356_route")


def test_stage356_engine_route_rejects_noncanonical_baseline_order() -> None:
    with pytest.raises(ValueError, match="baseline lookup order must begin"):
        _route(baseline_lookup_order=("unity::.dll", "unity/.dll")).validate(context="stage356_route")


def test_stage356_engine_route_rejects_blocked_learning_baseline() -> None:
    with pytest.raises(ValueError, match="learning baseline is blocked"):
        _route(blocked_baseline_keys=("unity/.dll",)).validate(context="stage356_route")


def test_stage356_engine_route_rejects_duplicate_embedded_types() -> None:
    with pytest.raises(ValueError, match="duplicate sniffed embedded types"):
        _route(sniffed_embedded_types=("pe", "pe")).validate(context="stage356_route")
