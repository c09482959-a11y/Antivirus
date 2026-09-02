from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.internal.immutable_output_support import (
    FrozenSchedulerMapping,
    frozen_scheduler_items_decision,
    frozen_scheduler_mapping_equality_decision,
)
from Virus_Scan.tests.support.static_inventory import read_python_file


class HostileFrozenSchedulerMapping(FrozenSchedulerMapping):
    touched = 0

    @property
    def _items(self):  # type: ignore[override]
        type(self).touched += 1
        raise AssertionError("subclass _items descriptor executed")


def _hostile_frozen_mapping() -> HostileFrozenSchedulerMapping:
    HostileFrozenSchedulerMapping.touched = 0
    return object.__new__(HostileFrozenSchedulerMapping)


def test_stage2103_frozen_items_decision_rejects_subclass_without_descriptor_hooks() -> None:
    hostile = _hostile_frozen_mapping()

    decision = frozen_scheduler_items_decision(hostile)

    assert HostileFrozenSchedulerMapping.touched == 0
    assert decision.accepted is False
    assert decision.reason == "not_exact_frozen_scheduler_mapping"
    assert decision.value_type == "HostileFrozenSchedulerMapping"
    assert decision.items == ()
    assert HostileFrozenSchedulerMapping.touched == 0


def test_stage2103_frozen_items_decision_replays_invalid_exact_item_shape() -> None:
    frozen = object.__new__(FrozenSchedulerMapping)
    object.__setattr__(frozen, "_items", (("safe", 1), ("bad",)))

    decision = frozen_scheduler_items_decision(frozen)

    assert decision.accepted is False
    assert decision.reason == "invalid_frozen_scheduler_item_shape"
    assert decision.value_type == "FrozenSchedulerMapping"
    assert decision.items == ()


def test_stage2103_frozen_mapping_equality_uses_typed_replayable_rejections() -> None:
    frozen = FrozenSchedulerMapping((("safe", 1),))

    unsupported = frozen_scheduler_mapping_equality_decision(frozen, object())
    matching_dict = frozen_scheduler_mapping_equality_decision(frozen, {"safe": 1})

    assert unsupported.equal is False
    assert unsupported.reason == "unsupported_comparison_type"
    assert matching_dict.equal is True
    assert matching_dict.reason == "dict_item_snapshot"
    assert (frozen == object()) is False
    assert frozen == {"safe": 1}


def test_stage2103_immutable_output_support_no_longer_contains_bare_rows() -> None:
    support_source = read_python_file(Path("Virus_Scan/scheduler/internal/immutable_output_support.py"))

    assert "frozen_scheduler_items_decision" in support_source
    assert "frozen_scheduler_items_exact" not in support_source
    assert "frozen_scheduler_mapping_equality_decision" in support_source
    assert "return None" not in support_source
    assert "return False" not in support_source
