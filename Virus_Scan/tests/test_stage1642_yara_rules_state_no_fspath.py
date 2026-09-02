from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.runtime.yara_rules_state import (
    YARA_SNAPSHOT_KEY_TEXT_UNAVAILABLE,
    YARA_SOURCE_PATH_TEXT_UNAVAILABLE,
    YaraLightSnapshot,
    YaraRulesSnapshot,
)


class HostilePathLike:
    touched = 0

    def __fspath__(self):  # pragma: no cover - must not be reached
        type(self).touched += 1
        raise AssertionError("PathLike.__fspath__ must not execute")

    def __str__(self):  # pragma: no cover - must not be reached
        type(self).touched += 1
        raise AssertionError("PathLike.__str__ must not execute")

    def __repr__(self):  # pragma: no cover - must not be reached
        type(self).touched += 1
        raise AssertionError("PathLike.__repr__ must not execute")


class HostileStrSubclass(str):
    touched = 0

    def __str__(self):  # pragma: no cover - must not be reached
        type(self).touched += 1
        raise AssertionError("str subclass __str__ must not execute")

    def __repr__(self):  # pragma: no cover - must not be reached
        type(self).touched += 1
        raise AssertionError("str subclass __repr__ must not execute")


def test_stage1642_yara_source_path_rejects_pathlike_without_fspath_or_string_hooks() -> None:
    HostilePathLike.touched = 0

    snapshot = YaraRulesSnapshot(source_path=HostilePathLike())

    assert HostilePathLike.touched == 0
    assert snapshot.source_path == YARA_SOURCE_PATH_TEXT_UNAVAILABLE


def test_stage1642_yara_source_path_rejects_str_subclass_without_hooks() -> None:
    HostileStrSubclass.touched = 0

    snapshot = YaraRulesSnapshot(source_path=HostileStrSubclass("rules.yar"))

    assert HostileStrSubclass.touched == 0
    assert snapshot.source_path == YARA_SOURCE_PATH_TEXT_UNAVAILABLE


def test_stage1642_yara_snapshot_value_rejects_str_subclass_as_evidence() -> None:
    HostileStrSubclass.touched = 0

    snapshot = YaraLightSnapshot(rules={"nested": HostileStrSubclass("unsafe")}, ok=True, loaded_count=1)

    rejected = snapshot.rules["nested"]
    assert HostileStrSubclass.touched == 0
    assert isinstance(rejected, MappingProxyType)
    assert rejected["unavailable_reason"] == "yara_snapshot_text_subclass_rejected"


def test_stage1642_yara_mapping_key_rejects_str_subclass_without_hooks() -> None:
    HostileStrSubclass.touched = 0

    snapshot = YaraLightSnapshot(rules={HostileStrSubclass("unsafe_key"): "value"}, ok=True, loaded_count=1)

    assert HostileStrSubclass.touched == 0
    assert snapshot.rules[YARA_SNAPSHOT_KEY_TEXT_UNAVAILABLE] == "value"
