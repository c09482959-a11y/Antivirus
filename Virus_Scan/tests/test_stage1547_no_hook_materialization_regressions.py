from __future__ import annotations

import json
from types import MappingProxyType

import pytest

from Virus_Scan.models.clustering.common import safe_cluster_text
from Virus_Scan.models.clustering.graph_context import ClusterGraphNodeRecord
from Virus_Scan.models.graph.common import coerce_graph_event_time, graph_finite_float, safe_graph_text_with_reason
from Virus_Scan.models.replay.detachment import detach_replay_payload_value, safe_replay_text
from Virus_Scan.models.replay_economics import replay_compress_metadata
from Virus_Scan.publication.model_evidence_projection.contract_sanitization import sanitize_contract_record
from Virus_Scan.publication.model_evidence_projection.safe_mapping import json_value
from Virus_Scan.reporting.evidence_line_rules import EVIDENCE_RULES


class HostileDefaultRepr:
    touched = 0
    __hash__ = object.__hash__

    def __str__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("do not call")


class HostileStrAndRepr:
    touched = 0
    __hash__ = object.__hash__

    def __str__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("do not call")

    def __repr__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("do not call")


class HostileFloat:
    touched = 0

    def __float__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("do not call")


class HostileInt:
    touched = 0

    def __int__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("do not call")


def test_stage1547_default_repr_custom_str_is_rejected_without_str_hook() -> None:
    HostileDefaultRepr.touched = 0
    value = HostileDefaultRepr()

    assert safe_cluster_text(value, default_text="cluster_unavailable") == "cluster_unavailable"
    graph_text, graph_reason = safe_graph_text_with_reason(value, "unsafe_text_value_rejected")
    assert graph_text == "unsupported_graph_text_type:HostileDefaultRepr"
    assert graph_reason == "unsafe_text_value_rejected"
    assert safe_replay_text(value) == ""

    detached = detach_replay_payload_value({value: value})
    compressed = replay_compress_metadata({value: value})
    projected = json_value({"opaque": value})
    sanitized, unavailable, failures = sanitize_contract_record(
        "markov_probability_record",
        {
            "ready": False,
            "probability": None,
            "support": 0,
            "count": 0,
            "vocab": 0,
            "smoothing": "none",
            "reason": value,
            "model_version": "probability_v1",
        },
    )

    assert any(key.startswith("<HostileDefaultRepr>#") for key in detached)
    assert next(iter(detached.values()))["unavailable_reason"] == "unsupported_replay_payload_value"
    assert next(iter(compressed.values()))["unavailable_reason"] == "unsupported_replay_metadata_type"
    assert projected["opaque"]["unavailable_reason"] == "unsupported_model_evidence_text"
    assert sanitized["reason_unavailable_reason"].startswith("non_text_probability")
    assert unavailable["markov_probability_record.reason"].startswith("non_text_probability")
    assert failures
    json.dumps({"detached": detached, "compressed": compressed, "projected": projected, "sanitized": sanitized}, sort_keys=True)
    assert HostileDefaultRepr.touched == 0


def test_stage1547_custom_str_and_repr_are_rejected_without_touching_either_hook() -> None:
    HostileStrAndRepr.touched = 0
    value = HostileStrAndRepr()

    assert safe_cluster_text(value, default_text="cluster_unavailable") == "cluster_unavailable"
    graph_text, graph_reason = safe_graph_text_with_reason(value, "unsafe_text_value_rejected")
    assert graph_text == "unsupported_graph_text_type:HostileStrAndRepr"
    assert graph_reason == "unsafe_text_value_rejected"
    detached = detach_replay_payload_value({value: value})
    compressed = replay_compress_metadata({value: value})
    projected = json_value({"opaque": value})

    assert next(iter(detached.values()))["unavailable_reason"] == "unsupported_replay_payload_value"
    assert next(iter(compressed.values()))["unavailable_reason"] == "unsupported_replay_metadata_type"
    assert projected["opaque"]["unavailable_reason"] == "unsupported_model_evidence_text"
    assert HostileStrAndRepr.touched == 0


def test_stage1547_graph_numeric_rejects_float_and_int_hooks_without_invocation() -> None:
    HostileFloat.touched = 0
    HostileInt.touched = 0

    float_result = graph_finite_float(HostileFloat(), default=2.0, reason="unsafe_numeric_value_rejected")
    int_result = graph_finite_float(HostileInt(), default=3.0, reason="unsafe_numeric_value_rejected")
    time_result = coerce_graph_event_time(HostileFloat())

    assert float_result == (2.0, "unsafe_numeric_value_rejected")
    assert int_result == (3.0, "unsafe_numeric_value_rejected")
    assert time_result == (None, "non_numeric_event_time")
    assert HostileFloat.touched == 0
    assert HostileInt.touched == 0


def test_stage1547_cluster_graph_record_materializes_nested_metadata_and_rejects_hostile_values() -> None:
    HostileDefaultRepr.touched = 0
    value = HostileDefaultRepr()
    record = ClusterGraphNodeRecord(
        node_key="node",
        available=True,
        present=True,
        empty=False,
        corrupt=False,
        unavailable_reason="",
        risk=1.0,
        tags=(),
        edges=(),
        metadata=MappingProxyType(
            {
                "nested": MappingProxyType({"values": frozenset({"beta", "alpha"})}),
                "hostile": value,
            }
        ),
    )

    materialized = record.to_json()

    assert materialized["metadata"]["nested"]["values"] == ["alpha", "beta"]
    assert materialized["metadata"]["hostile"]["unavailable_reason"] == "non_materializable_cluster_graph_value"
    json.dumps(materialized, sort_keys=True)
    assert HostileDefaultRepr.touched == 0


def _assert_deeply_immutable(value: object) -> None:
    assert not isinstance(value, (list, dict, set))
    if isinstance(value, tuple):
        for item in value:
            _assert_deeply_immutable(item)
    elif isinstance(value, frozenset):
        with pytest.raises(AttributeError):
            value.add("mutation_probe")  # type: ignore[attr-defined]
        for item in value:
            _assert_deeply_immutable(item)


def test_stage1547_evidence_rules_are_deep_policy_immutable() -> None:
    _assert_deeply_immutable(EVIDENCE_RULES)
    for prefix, rule_tags, patterns in EVIDENCE_RULES:
        assert isinstance(prefix, str)
        assert isinstance(rule_tags, frozenset)
        assert isinstance(patterns, tuple)
        with pytest.raises(AttributeError):
            rule_tags.add("mutation_probe")  # type: ignore[attr-defined]
        with pytest.raises(AttributeError):
            patterns.append("mutation_probe")  # type: ignore[attr-defined]
