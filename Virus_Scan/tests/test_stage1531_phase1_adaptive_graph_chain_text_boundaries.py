"""Stage 1531 Phase 1 adaptive graph-chain exact-text boundary regressions."""
from __future__ import annotations

from Virus_Scan.detection.scoring.adaptive.model_inputs import graph_chain_probability_from_layer


class HostileText(str):
    def __new__(cls, value: str):
        obj = str.__new__(cls, value)
        obj.str_calls = 0
        obj.strip_calls = 0
        obj.bool_calls = 0
        return obj

    def __str__(self):  # pragma: no cover - failure proves caller-owned __str__ was used
        self.str_calls += 1
        raise AssertionError("caller-owned __str__ was invoked")

    def strip(self, *args, **kwargs):  # pragma: no cover - failure proves caller-owned strip() was used
        self.strip_calls += 1
        raise AssertionError("caller-owned strip() was invoked")

    def __bool__(self):  # pragma: no cover - failure proves caller-owned truthiness was probed
        self.bool_calls += 1
        raise AssertionError("caller-owned truthiness was invoked")


class HostileObject:
    def __init__(self):
        self.str_calls = 0
        self.bool_calls = 0

    def __str__(self):  # pragma: no cover - failure proves raw str() was used
        self.str_calls += 1
        raise AssertionError("caller-owned __str__ was invoked")

    def __bool__(self):  # pragma: no cover - failure proves caller-owned truthiness was probed
        self.bool_calls += 1
        raise AssertionError("caller-owned truthiness was invoked")


def test_stage1531_graph_unavailable_reason_does_not_probe_hostile_text_hooks() -> None:
    reason = HostileText(" graph_offline ")

    probability, unavailable_reason = graph_chain_probability_from_layer(
        {"graph_unavailable_reason": reason, "score": 100.0, "hits": ("hit",)}
    )

    assert probability == 0.0
    assert unavailable_reason == "graph_offline"
    assert reason.str_calls == 0
    assert reason.strip_calls == 0
    assert reason.bool_calls == 0


def test_stage1531_graph_chain_hits_are_counted_without_stringifying_evidence_items() -> None:
    hit = HostileObject()
    propagated = HostileObject()

    probability, reason = graph_chain_probability_from_layer(
        {"ready": True, "score": 0.0, "hits": (hit,), "propagated_chains": (propagated,)}
    )

    assert probability == 0.14
    assert reason is None
    assert hit.str_calls == 0
    assert hit.bool_calls == 0
    assert propagated.str_calls == 0
    assert propagated.bool_calls == 0


def test_stage1531_graph_unavailable_reason_object_failure_is_explicit_degraded_evidence() -> None:
    reason = HostileObject()

    probability, unavailable_reason = graph_chain_probability_from_layer(
        {"graph_unavailable_reason": reason, "score": 100.0, "hits": ("hit",)}
    )

    assert probability == 0.0
    assert unavailable_reason == "graph_unavailable_reason_text_unavailable"
    assert reason.str_calls == 0
    assert reason.bool_calls == 0
