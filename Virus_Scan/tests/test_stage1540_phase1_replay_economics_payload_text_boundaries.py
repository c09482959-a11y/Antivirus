"""Stage 1540: replay economics/payload text boundaries must not use raw str()."""
from __future__ import annotations

import json
from collections.abc import Mapping

from Virus_Scan.models.api import replay_economics_contracts
from Virus_Scan.models.replay.api import detach_replay_payload_mapping, detach_replay_payload_value
from Virus_Scan.models.replay.learning_boundaries import has_non_empty_text_field
from Virus_Scan.models.replay_economics import ReplayEconomicsConfig, replay_compress_metadata, replay_should_retain


class _HostileObject:
    def __init__(self, label: str = "hostile") -> None:
        self.label = label
        self.str_calls = 0
        self.bool_calls = 0

    def __str__(self):  # pragma: no cover - failure proves raw str() was used
        self.str_calls += 1
        raise AssertionError(f"raw __str__ used for {self.label}")

    def __bool__(self):  # pragma: no cover - failure proves truthiness probing regressed
        self.bool_calls += 1
        raise AssertionError(f"truthiness used for {self.label}")


class _HostilePath:
    def __init__(self) -> None:
        self.fspath_calls = 0
        self.str_calls = 0

    def __fspath__(self):  # pragma: no cover - test fails if invoked
        self.fspath_calls += 1
        raise RuntimeError("path unavailable")

    def __str__(self):  # pragma: no cover - failure proves raw str() was used
        self.str_calls += 1
        raise AssertionError("raw path __str__ used")


class _HostileReplayMapping(Mapping[str, object]):
    def __init__(self, path: object) -> None:
        self.path = path

    def __getitem__(self, key: str) -> object:
        if key == "path":
            return self.path
        if key == "score":
            return 0
        if key == "replay_divergence":
            return False
        raise KeyError(key)

    def __iter__(self):
        return iter(("path", "score", "replay_divergence"))

    def __len__(self) -> int:
        return 3

    def get(self, key: str, default: object = None) -> object:
        try:
            return self[key]
        except KeyError:
            return default


def test_stage1540_replay_economics_metadata_compression_does_not_raw_str_keys_or_values() -> None:
    hostile_key = _HostileObject("metadata-key")
    hostile_value = _HostileObject("metadata-value")

    compressed = replay_compress_metadata({hostile_key: hostile_value, b"safe": bytearray(b"value")})

    assert compressed["safe"] == "value"
    hostile_slots = [value for key, value in compressed.items() if key.startswith("<unreadable_replay_metadata_key")]
    assert hostile_slots
    assert hostile_slots[0]["unavailable_reason"] == "unsupported_replay_metadata_type"
    assert hostile_slots[0]["value"] == "<_HostileObject>"
    json.dumps(compressed, sort_keys=True)


def test_stage1540_replay_retention_keeps_hostile_identity_without_raw_str() -> None:
    hostile_path = _HostilePath()
    result = _HostileReplayMapping(hostile_path)
    config = ReplayEconomicsConfig(sample_modulo=999_983, divergence_always_keep=True)

    assert replay_should_retain(result, index=1, config=config) is True
    assert replay_economics_contracts.replay_should_retain(result) is True
    assert hostile_path.fspath_calls == 0
    assert hostile_path.str_calls == 0


def test_stage1540_replay_payload_detachment_and_learning_text_do_not_raw_str() -> None:
    hostile_key = _HostileObject("payload-key")
    hostile_value = _HostileObject("payload-value")

    detached = detach_replay_payload_mapping({hostile_key: hostile_value, "safe": b"ok"})
    detached_value = detach_replay_payload_value(hostile_value)

    assert detached["safe"] == "ok"
    hostile_slots = [value for key, value in detached.items() if key.startswith("<_HostileObject>")]
    assert hostile_slots
    assert hostile_slots[0]["unavailable_reason"] == "unsupported_replay_payload_value"
    assert detached_value["unavailable_reason"] == "unsupported_replay_payload_value"
    assert has_non_empty_text_field({"field": hostile_value}, "field") is False
    json.dumps({"detached": detached, "value": detached_value}, sort_keys=True)
