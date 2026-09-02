"""Stage 1734: unreadable explanation feature-probability parents emit evidence."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Iterator

from Virus_Scan.publication.model_evidence_projection import build_model_evidence_final_json_fields


class HostileExplanationMapping(Mapping):
    iter_calls = 0
    len_calls = 0
    getitem_calls = 0
    get_calls = 0
    keys_calls = 0
    items_calls = 0
    values_calls = 0
    repr_calls = 0

    @classmethod
    def reset(cls) -> None:
        cls.iter_calls = 0
        cls.len_calls = 0
        cls.getitem_calls = 0
        cls.get_calls = 0
        cls.keys_calls = 0
        cls.items_calls = 0
        cls.values_calls = 0
        cls.repr_calls = 0

    @classmethod
    def touched(cls) -> int:
        return (
            cls.iter_calls
            + cls.len_calls
            + cls.getitem_calls
            + cls.get_calls
            + cls.keys_calls
            + cls.items_calls
            + cls.values_calls
            + cls.repr_calls
        )

    def __iter__(self) -> Iterator[object]:  # pragma: no cover - failure if invoked
        type(self).iter_calls += 1
        raise AssertionError("caller-owned explanation mapping iteration was invoked")

    def __len__(self) -> int:  # pragma: no cover - failure if invoked
        type(self).len_calls += 1
        raise AssertionError("caller-owned explanation mapping length was invoked")

    def __getitem__(self, key: object) -> object:  # pragma: no cover - failure if invoked
        type(self).getitem_calls += 1
        raise AssertionError("caller-owned explanation mapping item access was invoked")

    def get(self, key: object, default: object = None) -> object:  # pragma: no cover - failure if invoked
        type(self).get_calls += 1
        raise AssertionError("caller-owned explanation mapping get was invoked")

    def keys(self) -> object:  # pragma: no cover - failure if invoked
        type(self).keys_calls += 1
        raise AssertionError("caller-owned explanation mapping keys was invoked")

    def items(self) -> object:  # pragma: no cover - failure if invoked
        type(self).items_calls += 1
        raise AssertionError("caller-owned explanation mapping items was invoked")

    def values(self) -> object:  # pragma: no cover - failure if invoked
        type(self).values_calls += 1
        raise AssertionError("caller-owned explanation mapping values was invoked")

    def __repr__(self) -> str:  # pragma: no cover - failure if invoked
        type(self).repr_calls += 1
        raise AssertionError("caller-owned explanation mapping repr was invoked")


def test_stage1734_unreadable_explanation_mapping_becomes_feature_probability_evidence() -> None:
    hostile = HostileExplanationMapping()
    HostileExplanationMapping.reset()

    fields = build_model_evidence_final_json_fields({"explanation": hostile})

    evidence = fields["model_evidence"]
    assert evidence["unavailable_reasons"]["explanation.feature_probabilities"] == "unreadable_feature_probability_record"
    assert any(
        failure["model_name"] == "explanation.feature_probabilities"
        and failure["failure_type"] == "invalid_feature_probability_record"
        and failure["reason"] == "unreadable_feature_probability_record"
        for failure in evidence["model_failures"]
    )
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert HostileExplanationMapping.touched() == 0


def test_stage1734_plain_text_explanation_is_not_model_evidence() -> None:
    assert build_model_evidence_final_json_fields({"explanation": "benign explanation"}) == {}
