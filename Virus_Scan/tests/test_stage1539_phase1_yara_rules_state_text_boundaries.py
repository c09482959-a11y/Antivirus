from __future__ import annotations

import pytest

from Virus_Scan.runtime.yara_rules_state import (
    YARA_SNAPSHOT_KEY_TEXT_UNAVAILABLE,
    YARA_SOURCE_PATH_TEXT_UNAVAILABLE,
    YaraLightSnapshot,
    YaraRulesSnapshot,
    YaraRulesState,
)


class HostileText:
    def __str__(self) -> str:  # pragma: no cover - must not be reached
        raise AssertionError("raw __str__ must not be called")

    def __repr__(self) -> str:  # pragma: no cover - must not be reached
        raise AssertionError("raw __repr__ must not be called")

    def __bool__(self) -> bool:  # pragma: no cover - must not be reached
        raise AssertionError("truthiness must not be probed")


class HostilePath:
    def __fspath__(self) -> object:
        return HostileText()

    def __str__(self) -> str:  # pragma: no cover - must not be reached
        raise AssertionError("raw path __str__ must not be called")

    def __bool__(self) -> bool:  # pragma: no cover - must not be reached
        raise AssertionError("path truthiness must not be probed")


class StrSubclass(str):
    def __str__(self) -> str:  # pragma: no cover - must not be reached
        raise AssertionError("str subclass __str__ must not be called")


class BytesPath:
    def __fspath__(self) -> bytes:  # pragma: no cover - must not be reached
        raise AssertionError("PathLike.__fspath__ must not be called")


def test_stage1539_yara_snapshot_mapping_keys_do_not_call_hostile_text() -> None:
    snapshot = YaraLightSnapshot(
        rules={
            HostileText(): {HostileText(): ["kept"]},
            "stable_key": {"nested_key": "value"},
        },
        ok=True,
        loaded_count=1,
    )

    assert snapshot.rules["stable_key"]["nested_key"] == "value"
    assert snapshot.rules[YARA_SNAPSHOT_KEY_TEXT_UNAVAILABLE][YARA_SNAPSHOT_KEY_TEXT_UNAVAILABLE] == ("kept",)
    with pytest.raises(TypeError):
        snapshot.rules["new"] = "blocked"


def test_stage1539_yara_source_path_does_not_call_hostile_text_or_truthiness() -> None:
    direct = YaraRulesSnapshot(source_path=HostileText())
    state = YaraRulesState()
    state.set_primary_rules("compiled", source_path=HostilePath(), loaded_count=2)

    assert direct.source_path == YARA_SOURCE_PATH_TEXT_UNAVAILABLE
    assert state.primary_snapshot().source_path == YARA_SOURCE_PATH_TEXT_UNAVAILABLE
    assert state.primary_snapshot().loaded_count == 2


def test_stage1539_yara_source_path_rejects_pathlike_and_str_subclass_boundaries() -> None:
    direct = YaraRulesSnapshot(source_path=StrSubclass("rules.yar"))
    state = YaraRulesState()
    state.set_primary_rules("compiled", source_path=BytesPath(), loaded_count=3)

    assert direct.source_path == YARA_SOURCE_PATH_TEXT_UNAVAILABLE
    assert state.primary_snapshot().source_path == YARA_SOURCE_PATH_TEXT_UNAVAILABLE
    assert state.primary_snapshot().rules == "compiled"
