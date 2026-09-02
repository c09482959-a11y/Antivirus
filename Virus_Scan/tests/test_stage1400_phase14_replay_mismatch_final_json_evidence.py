"""Stage 1400: replay model mismatches must remain final-JSON/replay evidence."""

from __future__ import annotations

from Virus_Scan.models.api.replay_comparison_contracts import compare_model_evidence
from Virus_Scan.publication.model_evidence_projection import build_model_evidence_final_json_fields


def test_stage1400_replay_model_mismatch_requires_final_json_and_replay_record() -> None:
    comparison = compare_model_evidence(
        model_name="markov",
        expected={"probability": 0.25, "ready": True},
        actual={"probability": 0.5, "ready": True},
    )

    fields = build_model_evidence_final_json_fields(
        {"model_evidence": {"replay_model_comparison_record": comparison}}
    )

    evidence = fields["model_evidence"]
    replay_record = evidence["replay_model_comparison_record"]
    assert replay_record["matched"] is False
    assert replay_record["mismatch_fields"] == ("probability",)
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True


def test_stage1400_direct_replay_model_mismatch_requires_publication_flags() -> None:
    comparison = compare_model_evidence(
        model_name="temporal",
        expected={"stage_probability": None, "stage_probability_ready": False},
        actual={"stage_probability": 0.8, "stage_probability_ready": True},
    )

    fields = build_model_evidence_final_json_fields(
        {"replay_model_comparison_record": comparison}
    )

    evidence = fields["model_evidence"]
    assert evidence["replay_model_comparison_record"]["matched"] is False
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True


def test_stage1400_replay_matched_flag_shape_is_validated_as_contract_boolean() -> None:
    fields = build_model_evidence_final_json_fields(
        {
            "model_evidence": {
                "replay_model_comparison_record": {
                    "model_name": "graph",
                    "expected": {"risk": 0.1},
                    "actual": {"risk": 0.1},
                    "matched": "yes",
                    "mismatch_fields": (),
                    "model_version": "test",
                }
            }
        }
    )

    evidence = fields["model_evidence"]
    replay_record = evidence["replay_model_comparison_record"]
    assert replay_record["matched_unavailable_reason"] == "non_boolean_matched_flag"
    assert evidence["unavailable_reasons"]["replay_model_comparison_record.matched"] == "non_boolean_matched_flag"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert any(
        failure["affected_fields"] == ("replay_model_comparison_record", "matched")
        for failure in evidence["model_failures"]
    )


def test_stage1400_replay_comparison_record_missing_required_fields_is_not_clean() -> None:
    fields = build_model_evidence_final_json_fields(
        {
            "model_evidence": {
                "replay_model_comparison_record": {
                    "model_name": "cluster",
                    "expected": {"cluster": "a"},
                    "actual": {"cluster": "b"},
                    "mismatch_fields": ("cluster",),
                    "model_version": "test",
                }
            }
        }
    )

    evidence = fields["model_evidence"]
    assert evidence["replay_model_comparison_record"]["matched_unavailable_reason"] == "missing_replay_model_comparison_field"
    assert evidence["unavailable_reasons"]["replay_model_comparison_record.matched"] == "missing_replay_model_comparison_field"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert any(
        failure["reason"] == "missing_replay_model_comparison_field"
        and failure["affected_fields"] == ("replay_model_comparison_record", "matched")
        for failure in evidence["model_failures"]
    )


def test_stage1400_replay_mismatch_fields_shape_is_validated() -> None:
    fields = build_model_evidence_final_json_fields(
        {
            "model_evidence": {
                "replay_model_comparison_record": {
                    "model_name": "temporal",
                    "expected": {"stage_probability": 0.1},
                    "actual": {"stage_probability": 0.2},
                    "matched": False,
                    "mismatch_fields": "stage_probability",
                    "model_version": "test",
                }
            }
        }
    )

    evidence = fields["model_evidence"]
    replay_record = evidence["replay_model_comparison_record"]
    assert replay_record["mismatch_fields_unavailable_reason"] == "non_sequence_replay_mismatch_fields"
    assert evidence["unavailable_reasons"]["replay_model_comparison_record.mismatch_fields"] == "non_sequence_replay_mismatch_fields"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True


def test_stage1400_replay_mismatch_fields_are_materialized_deterministically() -> None:
    fields = build_model_evidence_final_json_fields(
        {
            "model_evidence": {
                "replay_model_comparison_record": {
                    "model_name": "temporal",
                    "expected": {"a": 1, "b": 2},
                    "actual": {"a": 2, "b": 3},
                    "matched": False,
                    "mismatch_fields": {"b", "a"},
                    "model_version": "test",
                }
            }
        }
    )

    evidence = fields["model_evidence"]
    assert evidence["replay_model_comparison_record"]["mismatch_fields"] == ("a", "b")
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
