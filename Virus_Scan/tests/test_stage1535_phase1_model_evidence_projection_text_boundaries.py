"""Stage 1535: publication model-evidence projection exact-text boundaries."""

from __future__ import annotations

from Virus_Scan.publication.model_evidence_projection import build_model_evidence_final_json_fields


class HostileModelEvidenceText:
    def __str__(self) -> str:  # pragma: no cover - contract is that this is never called
        raise RuntimeError("hostile model-evidence text hook must not escape")

    def __bool__(self) -> bool:  # pragma: no cover - truthiness must not be probed
        raise AssertionError("hostile model-evidence truthiness must not be probed")


class HostileModelEvidenceKey:
    def __str__(self) -> str:  # pragma: no cover - contract is that this is never called
        raise RuntimeError("hostile model-evidence key text hook must not escape")

    def __bool__(self) -> bool:  # pragma: no cover - truthiness must not be probed
        raise AssertionError("hostile model-evidence key truthiness must not be probed")


def _model_evidence(record: dict[object, object]) -> dict[str, object]:
    projected = build_model_evidence_final_json_fields(record)
    assert "model_evidence" in projected
    evidence = projected["model_evidence"]
    assert isinstance(evidence, dict)
    return evidence


def test_stage1535_existing_model_evidence_key_and_value_text_failures_are_explicit() -> None:
    evidence = _model_evidence(
        {
            "model_evidence": {
                HostileModelEvidenceKey(): {"markov": 0.5},
                "opaque_value": HostileModelEvidenceText(),
            }
        }
    )

    assert evidence["<HostileModelEvidenceKey>"]["unavailable_reason"] == "unreadable_model_evidence_key"
    assert evidence["opaque_value"]["unavailable_reason"] == "unsupported_model_evidence_text"
    assert evidence["opaque_value"]["value_type"] == "HostileModelEvidenceText"


def test_stage1535_existing_unavailable_reason_hostile_key_becomes_failure_evidence() -> None:
    evidence = _model_evidence(
        {"model_evidence": {"unavailable_reasons": {HostileModelEvidenceKey(): "cold_start"}}}
    )

    unavailable = evidence["unavailable_reasons"]
    failures = evidence["model_failures"]

    assert unavailable["model_evidence.unavailable_reasons.<HostileModelEvidenceKey>"] == "unreadable_model_unavailable_reason_key"
    assert any(
        failure["failure_type"] == "invalid_model_unavailable_reasons_record"
        and failure["reason"] == "unreadable_model_unavailable_reason_key"
        for failure in failures
    )
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True


def test_stage1535_nested_unavailable_reason_hostile_key_becomes_failure_evidence() -> None:
    evidence = _model_evidence(
        {
            "adaptive_learning": {
                "profile_coordinated": {
                    "unavailable_reasons": {HostileModelEvidenceKey(): "insufficient_history"}
                }
            }
        }
    )

    unavailable = evidence["unavailable_reasons"]

    assert (
        unavailable[
            "adaptive_learning.profile_coordinated.unavailable_reasons.<HostileModelEvidenceKey>"
        ]
        == "unreadable_model_unavailable_reason_key"
    )
    assert any(
        failure["model_name"]
        == "adaptive_learning.profile_coordinated.unavailable_reasons.<HostileModelEvidenceKey>"
        for failure in evidence["model_failures"]
    )
