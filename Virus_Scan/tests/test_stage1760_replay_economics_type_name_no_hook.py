from __future__ import annotations

import inspect
import json

from Virus_Scan.models import replay_economics
from Virus_Scan.models.replay_economics import replay_compress_metadata


class HostileNameMeta(type):
    touched = 0

    def __getattribute__(cls, name):
        if name == "__name__":
            type.__setattr__(cls, "touched", type.__getattribute__(cls, "touched") + 1)
            raise RuntimeError("do not read class name through metaclass hook")
        return type.__getattribute__(cls, name)


class HostileReplayMetadataValue(metaclass=HostileNameMeta):
    touched = 0

    def __str__(self):
        type.__setattr__(type(self), "touched", type.__getattribute__(type(self), "touched") + 1)
        raise RuntimeError("do not stringify replay metadata")

    def __repr__(self):
        type.__setattr__(type(self), "touched", type.__getattribute__(type(self), "touched") + 1)
        raise RuntimeError("do not repr replay metadata")

    def __format__(self, spec):
        type.__setattr__(type(self), "touched", type.__getattribute__(type(self), "touched") + 1)
        raise RuntimeError("do not format replay metadata")


def _reset() -> None:
    type.__setattr__(HostileNameMeta, "touched", 0)
    type.__setattr__(HostileReplayMetadataValue, "touched", 0)


def _touch_count() -> int:
    return type.__getattribute__(HostileNameMeta, "touched") + type.__getattribute__(HostileReplayMetadataValue, "touched")


def test_replay_economics_unsupported_value_type_name_uses_no_hook_type_name() -> None:
    _reset()
    key = HostileReplayMetadataValue()
    value = HostileReplayMetadataValue()

    compressed = replay_compress_metadata({key: value})

    assert _touch_count() == 0
    slot_values = list(compressed.values())
    assert len(slot_values) == 1
    assert slot_values[0] == {
        "value": "<HostileReplayMetadataValue>",
        "unavailable_reason": "unsupported_replay_metadata_type",
    }
    json.dumps(compressed, sort_keys=True)


def test_replay_economics_set_sorting_rejects_type_name_hook_without_stringifying() -> None:
    _reset()
    value = HostileReplayMetadataValue()

    compressed = replay_compress_metadata({"items": {"safe", value}})

    assert _touch_count() == 0
    assert compressed["items"][0] in ("safe", {"value": "<HostileReplayMetadataValue>", "unavailable_reason": "unsupported_replay_metadata_type"})
    assert any(
        item == {"value": "<HostileReplayMetadataValue>", "unavailable_reason": "unsupported_replay_metadata_type"}
        for item in compressed["items"]
    )
    json.dumps(compressed, sort_keys=True)


def test_replay_economics_source_uses_no_hook_type_name_for_metadata_fallbacks() -> None:
    source = inspect.getsource(replay_economics)

    assert "no_hook_type_name" in source
    assert "type(key).__name__" not in source
    assert "type(value).__name__" not in source
