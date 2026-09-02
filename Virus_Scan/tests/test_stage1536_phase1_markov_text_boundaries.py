"""Stage 1536: Markov behavior/probability text boundaries."""
from __future__ import annotations

from Virus_Scan.contracts.detection_observation import DetectionObservation
from Virus_Scan.models.markov.counters import counter_support, counter_target_count, markov_reason_text
from Virus_Scan.models.markov.flow import canonical_behavior_flow, safe_markov_text
from Virus_Scan.models.markov.probability import markov_pair_probability


class _HostileText(str):
    def __new__(cls, value: str):
        obj = str.__new__(cls, value)
        obj.str_calls = 0
        obj.strip_calls = 0
        obj.bool_calls = 0
        return obj

    def __str__(self):  # pragma: no cover - failure proves raw str() was used
        self.str_calls += 1
        raise AssertionError("hostile markov __str__ used")

    def strip(self, *args, **kwargs):  # pragma: no cover - failure proves caller strip was used
        self.strip_calls += 1
        raise AssertionError("hostile markov strip used")

    def __bool__(self):  # pragma: no cover - failure proves truthiness probing was used
        self.bool_calls += 1
        raise AssertionError("hostile markov bool used")


class _HostileObject:
    def __init__(self, label: str) -> None:
        self.label = label
        self.str_calls = 0
        self.bool_calls = 0

    def __str__(self):  # pragma: no cover - failure proves raw str() was used
        self.str_calls += 1
        raise AssertionError(f"raw markov object __str__ used for {self.label}")

    def __bool__(self):  # pragma: no cover - failure proves truthiness probing was used
        self.bool_calls += 1
        raise AssertionError(f"markov truthiness used for {self.label}")


def _assert_no_hooks(*values: object) -> None:
    for value in values:
        assert getattr(value, "str_calls", 0) == 0
        assert getattr(value, "strip_calls", 0) == 0
        assert getattr(value, "bool_calls", 0) == 0


def test_stage1536_behavior_flow_detaches_hostile_str_and_ignores_unsupported_objects() -> None:
    event = _HostileText(" api_download ")
    unsupported = _HostileObject("behavior-event")

    flow = canonical_behavior_flow([event, unsupported, {"tag": _HostileText(" tag_exec ")}])

    assert flow == ()
    _assert_no_hooks(event, unsupported)


def test_stage1536_markov_reason_and_counter_text_do_not_use_raw_object_str() -> None:
    key = _HostileObject("counter-key")
    target = _HostileText("exec")

    support, vocab, reason = counter_support({key: 2, target: 3})
    count, count_reason = counter_target_count({_HostileText("exec"): 4}, target)

    assert support == 3
    assert vocab == 1
    assert reason == "invalid_markov_target"
    assert count == 4
    assert count_reason == ""
    assert markov_reason_text(key, default_text="default_reason") == "default_reason"
    assert safe_markov_text(key, default_text="default_text_value") == "default_text_value"
    _assert_no_hooks(key, target)


def test_stage1536_markov_probability_public_inputs_do_not_call_hostile_text_hooks() -> None:
    source = _HostileObject("source-event")
    target = _HostileText(" exec ")
    stage = _HostileObject("stage")

    try:
        DetectionObservation.from_value(source)
    except TypeError:
        pass
    else:  # pragma: no cover
        raise AssertionError("arbitrary object crossed exact-current observation boundary")
    record = markov_pair_probability(source, target)

    assert record["ready"] is False
    assert record["probability"] is None
    assert record["reason"] == "malformed_markov_pair_public_input"
    _assert_no_hooks(source, target, stage)
