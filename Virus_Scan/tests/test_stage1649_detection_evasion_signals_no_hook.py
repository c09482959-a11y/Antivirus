from __future__ import annotations
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence

from collections.abc import Mapping

from Virus_Scan.detection.explainability.evasion_signals import detect_evasion_signals
from Virus_Scan.detection.scoring.adaptive.model_score import build_probability_features


class HostileTag:
    str_calls = 0
    bool_calls = 0

    def __bool__(self):  # pragma: no cover - must not be invoked
        type(self).bool_calls += 1
        raise AssertionError("tag truthiness hook invoked")

    def __str__(self):  # pragma: no cover - must not be invoked
        type(self).str_calls += 1
        raise AssertionError("tag str hook invoked")

    def __repr__(self):  # pragma: no cover - must not be invoked
        raise AssertionError("tag repr hook invoked")


class HostileTagIterable:
    iter_calls = 0
    bool_calls = 0

    def __bool__(self):  # pragma: no cover - must not be invoked
        type(self).bool_calls += 1
        raise AssertionError("tags truthiness hook invoked")

    def __iter__(self):  # pragma: no cover - must not be invoked
        type(self).iter_calls += 1
        raise AssertionError("tags iteration hook invoked")


class HostileNode:
    attr_calls = 0
    bool_calls = 0

    def __bool__(self):  # pragma: no cover - must not be invoked
        type(self).bool_calls += 1
        raise AssertionError("node truthiness hook invoked")

    def __getattribute__(self, name: str):  # pragma: no cover - edge attrs must not be probed
        if name in {"edges", "neighbors", "links"}:
            type(self).attr_calls += 1
            raise AssertionError("node edge attribute hook invoked")
        return object.__getattribute__(self, name)


class HostileMapping(Mapping):
    iter_calls = 0
    getitem_calls = 0
    len_calls = 0
    bool_calls = 0

    def __iter__(self):  # pragma: no cover - must not be invoked
        type(self).iter_calls += 1
        raise AssertionError("mapping iter hook invoked")

    def __getitem__(self, key):  # pragma: no cover - must not be invoked
        type(self).getitem_calls += 1
        raise AssertionError("mapping getitem hook invoked")

    def __len__(self):  # pragma: no cover - must not be invoked
        type(self).len_calls += 1
        raise AssertionError("mapping len hook invoked")

    def __bool__(self):  # pragma: no cover - must not be invoked
        type(self).bool_calls += 1
        raise AssertionError("mapping bool hook invoked")


def test_stage1649_evasion_signal_rejects_hostile_tag_objects_without_hooks() -> None:
    HostileTag.str_calls = 0
    HostileTag.bool_calls = 0
    score = detect_evasion_signals(["process_exec", HostileTag()], node={"edges": ["edge"]})
    assert score == 0.3
    assert HostileTag.str_calls == 0
    assert HostileTag.bool_calls == 0


def test_stage1649_evasion_signal_rejects_hostile_tag_iterable_without_hooks() -> None:
    HostileTagIterable.iter_calls = 0
    HostileTagIterable.bool_calls = 0
    score = detect_evasion_signals(HostileTagIterable(), node={"edges": ["edge"]})
    assert score == 0.0
    assert HostileTagIterable.iter_calls == 0
    assert HostileTagIterable.bool_calls == 0


def test_stage1649_evasion_signal_rejects_hostile_node_without_attribute_hooks() -> None:
    HostileNode.attr_calls = 0
    HostileNode.bool_calls = 0
    empty_score = detect_evasion_signals(["process_exec"], node={"edges": []})
    hostile_score = detect_evasion_signals(["process_exec"], node=HostileNode())
    assert empty_score == 0.7
    assert hostile_score == 0.3
    assert HostileNode.attr_calls == 0
    assert HostileNode.bool_calls == 0


def test_stage1649_adaptive_evasion_rejects_hostile_public_inputs_without_hooks() -> None:
    HostileMapping.iter_calls = 0
    HostileMapping.getitem_calls = 0
    HostileMapping.len_calls = 0
    HostileMapping.bool_calls = 0
    features = build_probability_features(
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
        tags=HostileMapping(),
        yara_hits=HostileMapping(),
        node={"path": "sample.exe"},
        curr_stage="runtime",
        prev_stage="binary",
        ordered_events=(),
    )
    assert features["p_evasion"] == 0.4
    assert "p_evasion_unavailable_reason" in features
    assert features["p_evasion_unavailable_reason"] in (None, "")
    assert HostileMapping.iter_calls == 0
    assert HostileMapping.getitem_calls == 0
    assert HostileMapping.len_calls == 0
    assert HostileMapping.bool_calls == 0
