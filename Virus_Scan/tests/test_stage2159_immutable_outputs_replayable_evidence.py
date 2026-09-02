from __future__ import annotations

from Virus_Scan.scheduler.internal.immutable_outputs import (
    immutable_tuple,
    immutable_tuple_decision,
    materialize_scheduler_mapping,
    materialize_scheduler_mapping_decision,
    tuple_pair_items_decision,
)


def test_stage2159_tuple_pair_items_rejects_bad_pair_with_replayable_decision() -> None:
    decision = tuple_pair_items_decision((("ok", 1), object()))

    assert decision.accepted is False
    assert decision.reason == "tuple_pair_item_shape_rejected"
    assert decision.value_type == "tuple"
    assert decision.failed_index == 1
    assert decision.items == ()


def test_stage2159_immutable_tuple_none_has_replayable_missing_decision() -> None:
    decision = immutable_tuple_decision(None)

    assert decision.accepted is False
    assert decision.reason == "scheduler_tuple_missing"
    assert decision.value_type == "NoneType"
    assert decision.items == ()
    assert isinstance(decision.evidence, dict)
    assert decision.evidence["final_json_must_record"] is True
    assert immutable_tuple(None) == ()


def test_stage2159_materialize_none_has_replayable_missing_decision() -> None:
    decision = materialize_scheduler_mapping_decision(None)

    assert decision.accepted is False
    assert decision.reason == "scheduler_mapping_value_missing"
    assert decision.value_type == "NoneType"
    assert decision.value is None
    assert isinstance(decision.evidence, dict)
    assert decision.evidence["checkpoint_must_record"] is True
    assert decision.evidence["replay_must_record"] is True
    assert materialize_scheduler_mapping(None) is None
