from __future__ import annotations

from types import MappingProxyType

import pytest

from Virus_Scan.runtime.yara_rules_state import (
    YARA_SNAPSHOT_KEY_TEXT_UNAVAILABLE,
    YaraLightSnapshot,
    YaraRulesSnapshot,
)


class HostileMapping(dict):
    def items(self):  # pragma: no cover - must not be reached
        raise AssertionError("mapping items hook was called")

    def keys(self):  # pragma: no cover - must not be reached
        raise AssertionError("mapping keys hook was called")

    def values(self):  # pragma: no cover - must not be reached
        raise AssertionError("mapping values hook was called")

    def __iter__(self):  # pragma: no cover - must not be reached
        raise AssertionError("mapping iter hook was called")

    def __getitem__(self, key):  # pragma: no cover - must not be reached
        raise AssertionError("mapping getitem hook was called")

    def get(self, key, default=None):  # pragma: no cover - must not be reached
        raise AssertionError("mapping get hook was called")


class HostileValue:
    def __str__(self):  # pragma: no cover - must not be reached
        raise AssertionError("value str hook was called")

    def __repr__(self):  # pragma: no cover - must not be reached
        raise AssertionError("value repr hook was called")

    def __iter__(self):  # pragma: no cover - must not be reached
        raise AssertionError("value iter hook was called")


class HostileNumeric:
    def __bool__(self):  # pragma: no cover - must not be reached
        raise AssertionError("numeric bool hook was called")

    def __int__(self):  # pragma: no cover - must not be reached
        raise AssertionError("numeric int hook was called")

    def __float__(self):  # pragma: no cover - must not be reached
        raise AssertionError("numeric float hook was called")

    def __repr__(self):  # pragma: no cover - must not be reached
        raise AssertionError("numeric repr hook was called")


class HostileMeta(type):
    def __getattribute__(cls, name):  # pragma: no cover - must not be reached
        if name in {"__name__", "__qualname__", "__module__"}:
            raise AssertionError("metaclass type-name hook was called")
        return super().__getattribute__(name)


class HostileTypedValue(metaclass=HostileMeta):
    def __repr__(self):  # pragma: no cover - must not be reached
        raise AssertionError("typed value repr hook was called")


def test_stage1570_yara_snapshot_rejects_hostile_mapping_proxy_without_hooks() -> None:
    hostile = HostileMapping({"rule": "value"})

    snapshot = YaraLightSnapshot(rules=MappingProxyType(hostile), ok=True, loaded_count=1)

    assert snapshot.rules["value"] is None
    assert snapshot.rules["unavailable_reason"] == "yara_snapshot_mapping_unreadable"
    with pytest.raises(TypeError):
        snapshot.rules["new"] = "blocked"


def test_stage1570_yara_snapshot_evidence_wraps_nested_unsupported_values_without_hooks() -> None:
    source = {
        HostileValue(): ["kept", HostileTypedValue()],
        "safe": {"nested": HostileValue()},
    }

    snapshot = YaraRulesSnapshot(rules=source, loaded_count=HostileNumeric(), source_path=None)
    source["safe"]["nested"] = "mutated"

    assert snapshot.loaded_count == 0
    assert YARA_SNAPSHOT_KEY_TEXT_UNAVAILABLE in snapshot.rules
    hostile_key_value = snapshot.rules[YARA_SNAPSHOT_KEY_TEXT_UNAVAILABLE]
    assert hostile_key_value[0] == "kept"
    assert hostile_key_value[1]["value"] is None
    assert hostile_key_value[1]["unavailable_reason"] == "yara_snapshot_value_unsupported"
    assert hostile_key_value[1]["value_type"] == "HostileTypedValue"
    assert snapshot.rules["safe"]["nested"]["unavailable_reason"] == "yara_snapshot_value_unsupported"
    assert snapshot.rules["safe"]["nested"]["value_type"] == "HostileValue"

    with pytest.raises(TypeError):
        snapshot.rules["safe"]["new"] = "blocked"


def test_stage1570_yara_snapshot_primitive_constructor_flags_do_not_probe_hooks() -> None:
    snapshot = YaraLightSnapshot(rules={"ok": True}, ok=HostileNumeric(), loaded_count=HostileNumeric(), import_error_logged=HostileNumeric())

    assert snapshot.ok is False
    assert snapshot.loaded_count == 0
    assert snapshot.import_error_logged is False
    assert snapshot.rules["ok"] is True
