from __future__ import annotations

from typing import Any, Iterator

from Virus_Scan.publication.model_evidence_projection.assembly import (
    apply_projected_records,
    build_model_evidence_final_json_fields,
    final_model_evidence_fields,
    merge_many,
)


class HostileBoolMapping(dict):
    def __bool__(self) -> bool:  # pragma: no cover - the assertion is no call
        raise AssertionError("model-evidence projection must not truth-test caller mappings")


class HostileBoolIterable:
    def __init__(self, values: tuple[Any, ...]) -> None:
        self._values = values

    def __iter__(self) -> Iterator[Any]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __bool__(self) -> bool:  # pragma: no cover - the assertion is no call
        raise AssertionError("model-evidence projection must not truth-test caller containers")


class HostileBoolFlag:
    def __bool__(self) -> bool:  # pragma: no cover - the assertion is no call
        raise AssertionError("model-evidence projection must not truth-test caller flags")


def test_stage1486_merge_many_does_not_truth_test_mapping_inputs() -> None:
    left = HostileBoolMapping({"markov": 0.25})
    right = HostileBoolMapping({"temporal": 0.75})

    assert merge_many(left, right) == {"markov": 0.25, "temporal": 0.75}


def test_stage1486_apply_projected_records_does_not_truth_test_projected_maps() -> None:
    evidence: dict[str, Any] = {}

    apply_projected_records(
        evidence,
        direct_contract_records={},
        nested_contract_records={},
        projected_probabilities=HostileBoolMapping({"graph": 0.4}),
        unavailable=HostileBoolMapping({"temporal": "cold_start"}),
        existing_failures=(),
        failures=(),
    )

    assert evidence["feature_probabilities"] == {"graph": 0.4}
    assert evidence["unavailable_reasons"] == {"temporal": "cold_start"}


def test_stage1486_final_model_evidence_fields_does_not_truth_test_existing_flags_or_failures() -> None:
    evidence: dict[str, Any] = {
        "feature_probabilities": {"profile": 0.5},
        "model_failures": HostileBoolIterable(({"model_name": "profile", "reason": "degraded"},)),
        "final_json_must_record": HostileBoolFlag(),
        "replay_record_required": HostileBoolFlag(),
    }

    out = final_model_evidence_fields(evidence)

    projected = out["model_evidence"]
    assert projected["final_json_must_record"] is True
    assert projected["replay_record_required"] is True
    assert projected["model_failures"] is evidence["model_failures"]


def test_stage1486_build_model_evidence_fields_does_not_truth_test_record_or_probability_maps() -> None:
    record = HostileBoolMapping(
        {
            "feature_probabilities": HostileBoolMapping({"markov": 0.8}),
            "model_evidence": HostileBoolMapping(
                {
                    "unavailable_reasons": HostileBoolMapping({"temporal": "cold_start"}),
                    "final_json_must_record": HostileBoolFlag(),
                }
            ),
        }
    )

    out = build_model_evidence_final_json_fields(record)

    projected = out["model_evidence"]
    assert projected["feature_probabilities"]["markov"] == 0.8
    assert projected["unavailable_reasons"]["temporal"] == "cold_start"
    assert projected["final_json_must_record"] is True
    assert projected["replay_record_required"] is True
