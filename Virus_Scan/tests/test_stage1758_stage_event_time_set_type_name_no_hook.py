from __future__ import annotations

import inspect

from Virus_Scan.contracts import stage_event_time
from Virus_Scan.contracts.stage_event_time import deterministic_stage_event_time


class HostileNameMeta(type):
    touched = 0

    def __getattribute__(cls, name):
        if name == "__name__":
            type.__setattr__(cls, "touched", type.__getattribute__(cls, "touched") + 1)
            raise RuntimeError("do not read class name through metaclass hook")
        return type.__getattribute__(cls, name)


class HostileStageTag(metaclass=HostileNameMeta):
    touched = 0

    def __str__(self):
        type.__setattr__(type(self), "touched", type.__getattribute__(type(self), "touched") + 1)
        raise RuntimeError("do not stringify stage tag")

    def __repr__(self):
        type.__setattr__(type(self), "touched", type.__getattribute__(type(self), "touched") + 1)
        raise RuntimeError("do not repr stage tag")

    def __format__(self, spec):
        type.__setattr__(type(self), "touched", type.__getattribute__(type(self), "touched") + 1)
        raise RuntimeError("do not format stage tag")


def _reset() -> None:
    type.__setattr__(HostileNameMeta, "touched", 0)
    type.__setattr__(HostileStageTag, "touched", 0)


def _touch_count() -> int:
    return type.__getattribute__(HostileNameMeta, "touched") + type.__getattribute__(HostileStageTag, "touched")


def test_stage_event_time_set_tag_type_name_sort_rejects_hostile_metaclass_without_hooks() -> None:
    _reset()
    hostile = HostileStageTag()

    first = deterministic_stage_event_time("sample.bin", "asset", {"safe-tag", hostile})
    second = deterministic_stage_event_time("sample.bin", "asset", {"safe-tag", hostile})

    assert 0.0 <= first < 1.0
    assert first == second
    assert _touch_count() == 0


def test_stage_event_time_source_uses_no_hook_type_name_for_set_tag_sorting() -> None:
    source = inspect.getsource(stage_event_time)

    assert "no_hook_type_name(item)" in source
    assert "type(item).__name__" not in source
