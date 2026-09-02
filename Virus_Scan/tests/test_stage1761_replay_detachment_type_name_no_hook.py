from __future__ import annotations

import inspect
import json

from Virus_Scan.models.replay import detachment
from Virus_Scan.models.replay.detachment import (
    detach_replay_payload_mapping,
    detach_replay_payload_sequence,
    detach_replay_payload_value,
    replay_payload_key_order,
)


class HostileNameMeta(type):
    touched = 0

    def __getattribute__(cls, name):
        if name == "__name__":
            type.__setattr__(cls, "touched", type.__getattribute__(cls, "touched") + 1)
            raise RuntimeError("do not read class name through metaclass hook")
        return type.__getattribute__(cls, name)


class HostileReplayPayloadValue(metaclass=HostileNameMeta):
    touched = 0

    def __str__(self):
        type.__setattr__(type(self), "touched", type.__getattribute__(type(self), "touched") + 1)
        raise RuntimeError("do not stringify replay payload")

    def __repr__(self):
        type.__setattr__(type(self), "touched", type.__getattribute__(type(self), "touched") + 1)
        raise RuntimeError("do not repr replay payload")

    def __format__(self, spec):
        type.__setattr__(type(self), "touched", type.__getattribute__(type(self), "touched") + 1)
        raise RuntimeError("do not format replay payload")


class HostileMapping:
    touched = 0

    def __iter__(self):
        type.__setattr__(type(self), "touched", type.__getattribute__(type(self), "touched") + 1)
        raise RuntimeError("do not iterate mapping-like object")

    def __str__(self):
        type.__setattr__(type(self), "touched", type.__getattribute__(type(self), "touched") + 1)
        raise RuntimeError("do not stringify mapping-like object")

    def __repr__(self):
        type.__setattr__(type(self), "touched", type.__getattribute__(type(self), "touched") + 1)
        raise RuntimeError("do not repr mapping-like object")


def _reset() -> None:
    type.__setattr__(HostileNameMeta, "touched", 0)
    type.__setattr__(HostileReplayPayloadValue, "touched", 0)
    type.__setattr__(HostileMapping, "touched", 0)


def _touch_count() -> int:
    return (
        type.__getattribute__(HostileNameMeta, "touched")
        + type.__getattribute__(HostileReplayPayloadValue, "touched")
        + type.__getattribute__(HostileMapping, "touched")
    )


def test_replay_detachment_key_and_value_type_fallbacks_use_no_hook_type_name() -> None:
    _reset()
    key = HostileReplayPayloadValue()
    value = HostileReplayPayloadValue()

    detached = detach_replay_payload_value({key: value})

    assert _touch_count() == 0
    assert any(k.startswith("<HostileReplayPayloadValue>#") for k in detached)
    slot = next(iter(detached.values()))
    assert slot == {
        "value": None,
        "unavailable_reason": "unsupported_replay_payload_value",
        "value_type": "HostileReplayPayloadValue",
    }
    json.dumps(detached, sort_keys=True)


def test_replay_detachment_sequence_and_mapping_rejection_type_names_do_not_call_hooks() -> None:
    _reset()
    value = HostileReplayPayloadValue()
    mapping_like = HostileMapping()

    seq = detach_replay_payload_sequence(value)
    mapping = detach_replay_payload_mapping(mapping_like)
    key_order = replay_payload_key_order(value)

    assert _touch_count() == 0
    assert seq == [{
        "value": None,
        "unavailable_reason": "unsupported_replay_payload_sequence",
        "value_type": "HostileReplayPayloadValue",
    }]
    assert mapping["unavailable_reason"] == "unsupported_replay_payload_mapping"
    assert mapping["value_type"] == "HostileMapping"
    assert key_order == "<HostileReplayPayloadValue>"
    json.dumps({"seq": seq, "mapping": mapping, "key_order": key_order}, sort_keys=True)


def test_replay_detachment_set_sorting_uses_no_hook_type_name_without_stringifying() -> None:
    _reset()
    value = HostileReplayPayloadValue()

    detached = detach_replay_payload_value({"items": {"safe", value}})

    assert _touch_count() == 0
    assert any(
        item == {"value": None, "unavailable_reason": "unsupported_replay_payload_value", "value_type": "HostileReplayPayloadValue"}
        for item in detached["items"]
    )
    json.dumps(detached, sort_keys=True)


def test_replay_detachment_source_removed_type_name_hook_paths() -> None:
    source = inspect.getsource(detachment)

    assert "no_hook_type_name" in source
    assert "type(key).__name__" not in source
    assert "type(value).__name__" not in source
