from __future__ import annotations

import inspect

from Virus_Scan.scheduler.ownership import inmemory_live_state
from Virus_Scan.scheduler.ownership.inmemory_live_state import InMemoryLiveSchedulerState


class HostileLiveValue:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("str hook executed")

    def __repr__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("repr hook executed")

    def __format__(self, _spec):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("format hook executed")

    def __float__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("float hook executed")

    def __int__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("int hook executed")

    def __bool__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("bool hook executed")


def test_stage1870_live_state_rejection_field_names_do_not_execute_hostile_hooks():
    HostileLiveValue.reset()
    hostile_key = HostileLiveValue()
    hostile_set_item = HostileLiveValue()
    hostile_ewma_key = HostileLiveValue()
    hostile_ewma_value = HostileLiveValue()

    state = InMemoryLiveSchedulerState(
        active={hostile_key: {"safe": "value"}},
        done=(hostile_set_item,),
        ewma_state={hostile_ewma_key: 1.0, "ok": hostile_ewma_value},
    )

    fields = {entry["field"] for entry in state.constructor_rejections}

    assert HostileLiveValue.touched == 0
    assert "active_key_0" in fields
    assert "done_0" in fields
    assert "ewma_state_key_0" in fields
    assert "ewma_state_value_ok" in fields


def test_stage1870_live_state_source_has_no_rejection_fstrings():
    source = inspect.getsource(inmemory_live_state)

    assert 'f"{field_name}_key_{index}"' not in source
    assert 'f"{field_name}_{index}"' not in source
    assert 'f"ewma_state_key_{index}"' not in source
    assert 'f"ewma_state_value_{key_text}"' not in source
    assert "ewma_state_value_" + str.__str__("ok") == "ewma_state_value_ok"
