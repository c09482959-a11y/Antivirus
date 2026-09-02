"""Stage 1412: parent replay payload detachment is JSON-safe for hostile values."""

from __future__ import annotations

import json
from collections.abc import Mapping

from Virus_Scan.models.replay.api import detach_replay_payload_mapping, detach_replay_payload_value


class HostileText:
    def __str__(self):
        raise RuntimeError("string unavailable")

    def __repr__(self):
        raise RuntimeError("repr unavailable")


class HostileMapping(Mapping):
    def __iter__(self):
        raise RuntimeError("iteration unavailable")

    def __len__(self):
        raise RuntimeError("length unavailable")

    def __getitem__(self, key):
        raise RuntimeError("value unavailable")

    def keys(self):
        raise RuntimeError("keys unavailable")


def test_stage1412_replay_payload_detach_absorbs_hostile_mapping_keys_and_values() -> None:
    hostile_key = HostileText()
    detached = detach_replay_payload_mapping({hostile_key: HostileText(), "safe": 1})

    hostile_slots = [value for key, value in detached.items() if key.startswith("<HostileText>")]
    assert hostile_slots
    assert hostile_slots[0]["unavailable_reason"] == "unsupported_replay_payload_value"
    assert detached["safe"] == 1
    json.dumps(detached, sort_keys=True)


def test_stage1412_replay_payload_detach_absorbs_unreadable_mappings_and_sets() -> None:
    detached_mapping = detach_replay_payload_value(HostileMapping())
    detached_set = detach_replay_payload_value({HostileText()})

    assert detached_mapping["unavailable_reason"] == "unreadable_replay_payload_mapping_keys"
    assert detached_set[0]["unavailable_reason"] == "unsupported_replay_payload_value"
    json.dumps({"mapping": detached_mapping, "set": detached_set}, sort_keys=True)
