from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch

from Virus_Scan.detection.profiles import baseline_snapshot
from Virus_Scan.detection.registries.immutability import freeze_registry_value


class HostileNameMeta(type):
    name_touches = 0

    def __getattribute__(cls, name):  # pragma: no cover - failure proves unsafe type-name access
        if name == "__name__":
            HostileNameMeta.name_touches += 1
            raise RuntimeError("caller-owned metaclass __name__ executed")
        return super().__getattribute__(name)


class HostileRegistryKey(metaclass=HostileNameMeta):
    str_touches = 0
    repr_touches = 0
    format_touches = 0

    def __str__(self):  # pragma: no cover - failure proves unsafe string conversion
        type(self).str_touches += 1
        raise RuntimeError("caller-owned __str__ executed")

    def __repr__(self):  # pragma: no cover - failure proves unsafe repr conversion
        type(self).repr_touches += 1
        raise RuntimeError("caller-owned __repr__ executed")

    def __format__(self, spec):  # pragma: no cover - failure proves unsafe format conversion
        type(self).format_touches += 1
        raise RuntimeError("caller-owned __format__ executed")


class HostileRegistryValue(metaclass=HostileNameMeta):
    str_touches = 0
    repr_touches = 0
    iter_touches = 0

    def __str__(self):  # pragma: no cover - failure proves unsafe string conversion
        type(self).str_touches += 1
        raise RuntimeError("caller-owned value __str__ executed")

    def __repr__(self):  # pragma: no cover - failure proves unsafe repr conversion
        type(self).repr_touches += 1
        raise RuntimeError("caller-owned value __repr__ executed")

    def __iter__(self):  # pragma: no cover - failure proves unsafe iteration
        type(self).iter_touches += 1
        raise RuntimeError("caller-owned value __iter__ executed")


class HostileMapping(Mapping):
    keys_touches = 0
    iter_touches = 0
    getitem_touches = 0
    len_touches = 0

    def keys(self):  # pragma: no cover - failure proves arbitrary mapping method access
        type(self).keys_touches += 1
        raise RuntimeError("caller-owned keys executed")

    def __iter__(self):  # pragma: no cover - failure proves arbitrary mapping iteration
        type(self).iter_touches += 1
        raise RuntimeError("caller-owned iter executed")

    def __getitem__(self, key):  # pragma: no cover - failure proves arbitrary mapping item access
        type(self).getitem_touches += 1
        raise RuntimeError("caller-owned getitem executed")

    def __len__(self):  # pragma: no cover - failure proves arbitrary mapping length access
        type(self).len_touches += 1
        raise RuntimeError("caller-owned len executed")


def _reset() -> None:
    HostileNameMeta.name_touches = 0
    HostileRegistryKey.str_touches = 0
    HostileRegistryKey.repr_touches = 0
    HostileRegistryKey.format_touches = 0
    HostileRegistryValue.str_touches = 0
    HostileRegistryValue.repr_touches = 0
    HostileRegistryValue.iter_touches = 0
    HostileMapping.keys_touches = 0
    HostileMapping.iter_touches = 0
    HostileMapping.getitem_touches = 0
    HostileMapping.len_touches = 0


def _plain(value):
    if type(value) is MappingProxyType:
        return {key: _plain(item) for key, item in value.items()}
    if type(value) is dict:
        return {key: _plain(item) for key, item in value.items()}
    if type(value) in (tuple, list):
        return tuple(_plain(item) for item in value)
    if type(value) in (set, frozenset):
        return tuple(sorted((_plain(item) for item in value), key=lambda item: str(item)))
    return value


def test_stage1769_freeze_registry_value_rejects_hostile_keys_without_hooks() -> None:
    _reset()
    frozen = freeze_registry_value({HostileRegistryKey(): {"safe": HostileRegistryValue()}})
    materialized = _plain(frozen)

    assert materialized["registry_key_0"]["unavailable_reason"] == "invalid_key_type"
    assert materialized["registry_key_0"]["value_type"] == "HostileRegistryKey"
    assert HostileNameMeta.name_touches == 0
    assert HostileRegistryKey.str_touches == 0
    assert HostileRegistryKey.repr_touches == 0
    assert HostileRegistryKey.format_touches == 0
    assert HostileRegistryValue.str_touches == 0
    assert HostileRegistryValue.repr_touches == 0
    assert HostileRegistryValue.iter_touches == 0


def test_stage1769_freeze_registry_value_rejects_unknown_mapping_without_mapping_hooks() -> None:
    _reset()
    frozen = freeze_registry_value(HostileMapping())
    materialized = _plain(frozen)

    assert materialized["unavailable_reason"] == "detection_registry_mapping_unavailable"
    assert materialized["value_type"] == "HostileMapping"
    assert HostileMapping.keys_touches == 0
    assert HostileMapping.iter_touches == 0
    assert HostileMapping.getitem_touches == 0
    assert HostileMapping.len_touches == 0


def test_stage2023_freeze_registry_value_suffixes_duplicate_keys_without_fstrings() -> None:
    frozen = freeze_registry_value({b"dup": 1, "dup": 2})
    materialized = _plain(frozen)

    assert materialized["dup"] == 1
    assert materialized["dup#1"] == 2


def test_stage1769_profile_baseline_snapshot_rejects_hostile_mapping_inputs_without_hooks() -> None:
    _reset()
    hostile_baseline = {
        "files": 1,
        HostileRegistryKey(): {"nested": HostileRegistryValue()},
        "behavior_buckets": HostileMapping(),
    }

    with patch.object(baseline_snapshot, "get_extension_baseline", lambda engine, file_path: hostile_baseline):
        snapshot = _plain(baseline_snapshot.read_extension_baseline_snapshot("renpy", "game.rpy"))

    assert snapshot["profile_baseline_key_1"]["unavailable_reason"] == "invalid_key_type"
    assert snapshot["profile_baseline_key_1"]["value_type"] == "HostileRegistryKey"
    assert snapshot["behavior_buckets"]["unavailable_reason"] == "profile_baseline_mapping_unavailable"
    assert snapshot["behavior_buckets"]["value_type"] == "HostileMapping"
    assert HostileNameMeta.name_touches == 0
    assert HostileRegistryKey.str_touches == 0
    assert HostileRegistryKey.repr_touches == 0
    assert HostileRegistryValue.str_touches == 0
    assert HostileRegistryValue.repr_touches == 0
    assert HostileRegistryValue.iter_touches == 0
    assert HostileMapping.keys_touches == 0
    assert HostileMapping.iter_touches == 0
    assert HostileMapping.getitem_touches == 0
    assert HostileMapping.len_touches == 0


def test_stage1769_profile_baseline_snapshot_suffixes_duplicate_materialized_keys_without_fstrings() -> None:
    baseline = {b"dup": 1, "dup": 2}

    with patch.object(baseline_snapshot, "get_extension_baseline", lambda engine, file_path: baseline):
        snapshot = _plain(baseline_snapshot.read_extension_baseline_snapshot("renpy", "game.rpy"))

    assert snapshot["dup"] == 1
    assert snapshot["dup#1"] == 2


def test_stage1769_detection_registry_and_profile_sources_block_raw_materialization() -> None:
    registry_source = read_python_file(Path("Virus_Scan/detection/registries/immutability.py"))
    baseline_source = read_python_file(Path("Virus_Scan/detection/profiles/baseline_snapshot.py"))
    constants_source = read_python_file(Path("Virus_Scan/detection/registries/constants_defaults.py"))

    for source in (registry_source, baseline_source):
        assert "type(value).__name__" not in source
        assert "value!r" not in source
        assert "str(key)" not in source
        assert "value.keys()" not in source
        assert "value[key]" not in source
        assert "no_hook_mapping_items" in source
        assert "no_hook_type_name" in source
    assert 'key_text = f"{key_text}#{index}"' not in registry_source
    assert 'key_text = f"{key_text}#{index}"' not in baseline_source
    assert '"probability": safe_clamp(count / files)' not in baseline_source
    assert "TAG_ALIAS_REPORTING_MAP = freeze_registry_value" not in constants_source
    assert "TAG_REPORTING_CANONICAL_NAMES" in constants_source
