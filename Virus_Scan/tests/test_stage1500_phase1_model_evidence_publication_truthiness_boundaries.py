from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.publication.model_evidence_projection.record_validation import (
    contract_record_terminal_name,
)
from Virus_Scan.publication.model_evidence_projection.unavailable_projection import (
    invalid_unavailable_reason_key_reason,
)
from Virus_Scan.publication.model_evidence_projection import build_model_evidence_final_json_fields


class HostileBoolEqText:
    def __init__(self, value: str) -> None:
        self.value = value
        self.bool_calls = 0
        self.eq_calls = 0
        self.str_calls = 0
        self.repr_calls = 0

    def __str__(self) -> str:  # pragma: no cover - failure if invoked
        self.str_calls += 1
        raise AssertionError("caller-owned model-evidence __str__ was invoked")

    def __repr__(self) -> str:  # pragma: no cover - failure if invoked
        self.repr_calls += 1
        raise AssertionError("caller-owned model-evidence __repr__ was invoked")

    def __bool__(self) -> bool:  # pragma: no cover - test fails if invoked
        self.bool_calls += 1
        raise AssertionError("caller-owned model-evidence truthiness was probed")

    def __eq__(self, other: object) -> bool:  # pragma: no cover - test fails if invoked
        self.eq_calls += 1
        raise AssertionError("caller-owned model-evidence equality was probed")


class HostileBoolEqObject:
    def __init__(self) -> None:
        self.bool_calls = 0
        self.eq_calls = 0

    def __repr__(self) -> str:
        return "HostileBoolEqObject()"

    def __bool__(self) -> bool:  # pragma: no cover - test fails if invoked
        self.bool_calls += 1
        raise AssertionError("caller-owned object truthiness was probed")

    def __eq__(self, other: object) -> bool:  # pragma: no cover - test fails if invoked
        self.eq_calls += 1
        raise AssertionError("caller-owned object equality was probed")


def test_stage1500_non_mapping_existing_model_evidence_does_not_probe_truthiness_or_equality() -> None:
    hostile = HostileBoolEqObject()

    fields = build_model_evidence_final_json_fields({"model_evidence": hostile})

    evidence = fields["model_evidence"]
    assert evidence["unavailable_reasons"]["model_evidence"] == "non_mapping_model_evidence_record"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert hostile.bool_calls == 0
    assert hostile.eq_calls == 0


def test_stage1500_non_mapping_feature_probability_container_does_not_probe_truthiness_or_equality() -> None:
    hostile = HostileBoolEqObject()

    fields = build_model_evidence_final_json_fields({"feature_probabilities": hostile})

    evidence = fields["model_evidence"]
    assert evidence["unavailable_reasons"]["feature_probabilities"] == "non_mapping_feature_probability_record"
    assert evidence["model_failures"][0]["failure_type"] == "invalid_feature_probability_record"
    assert hostile.bool_calls == 0
    assert hostile.eq_calls == 0


def test_stage1500_model_failure_required_fields_do_not_probe_text_truthiness() -> None:
    hostile_model_name = HostileBoolEqText("markov")

    fields = build_model_evidence_final_json_fields(
        {
            "model_evidence": {
                "model_failures": [
                    {
                        "model_name": hostile_model_name,
                        "failure_type": "model_unavailable",
                        "reason": "cold_start",
                        "affected_fields": ("markov",),
                    }
                ]
            }
        }
    )

    evidence = fields["model_evidence"]
    assert evidence["model_failures"][0]["model_name"] == "model_evidence.model_failures"
    assert evidence["model_failures"][0]["failure_type"] == "invalid_model_failure_record"
    assert hostile_model_name.bool_calls == 0
    assert hostile_model_name.eq_calls == 0
    assert hostile_model_name.str_calls == 0
    assert hostile_model_name.repr_calls == 0


def test_stage1500_publication_record_helper_does_not_probe_field_name_truthiness() -> None:
    field_name = HostileBoolEqText("outer.probability_record")
    reason_key = HostileBoolEqText("markov")

    assert contract_record_terminal_name(field_name) == "<HostileBoolEqText>"
    assert invalid_unavailable_reason_key_reason(reason_key) == "unreadable_model_unavailable_reason_key"
    assert field_name.bool_calls == 0
    assert field_name.eq_calls == 0
    assert field_name.str_calls == 0
    assert field_name.repr_calls == 0
    assert reason_key.bool_calls == 0
    assert reason_key.eq_calls == 0
    assert reason_key.str_calls == 0
    assert reason_key.repr_calls == 0


def test_stage1500_model_evidence_projection_no_longer_uses_truthiness_blank_boundary_forms() -> None:
    checked = {
        Path("Virus_Scan/publication/model_evidence_projection/assembly.py"),
        Path("Virus_Scan/publication/model_evidence_projection/container_candidates.py"),
        Path("Virus_Scan/publication/model_evidence_projection/contract_records.py"),
        Path("Virus_Scan/publication/model_evidence_projection/model_failure_sanitization.py"),
        Path("Virus_Scan/publication/model_evidence_projection/probability_validation.py"),
        Path("Virus_Scan/publication/model_evidence_projection/record_validation.py"),
        Path("Virus_Scan/publication/model_evidence_projection/unavailable_projection.py"),
    }
    forbidden_snippets = (
        'value == ""',
        'existing_evidence == ""',
        'field_name or ""',
        'key or ""',
        'safe_mapping_get(value, required) or ""',
    )
    for path in checked:
        source = path.read_text(encoding="utf-8")
        for snippet in forbidden_snippets:
            assert snippet not in source
        ast.parse(source, filename=str(path))
