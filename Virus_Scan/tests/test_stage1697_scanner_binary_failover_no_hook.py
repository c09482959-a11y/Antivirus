from __future__ import annotations

import ast
from pathlib import Path

import pytest

from Virus_Scan.scanners.binary_failover import _is_only_filetype_tags, should_binary_failover
from Virus_Scan.scanners.binary_failover_policy import renpy_container_without_payload_evidence


class HostileText:
    touched = 0

    def __str__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("do not repr")

    def __format__(self, spec: str) -> str:
        type(self).touched += 1
        raise RuntimeError("do not format")


class HostileTags:
    touched = 0

    def __bool__(self) -> bool:
        type(self).touched += 1
        raise RuntimeError("do not bool")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __repr__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("do not repr")


class HostileKey:
    touched = 0

    def __hash__(self) -> int:
        return hash("ext")

    def __eq__(self, other: object) -> bool:
        type(self).touched += 1
        raise RuntimeError("do not compare")

    def __repr__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("do not repr")


def test_binary_failover_rejects_hostile_tag_object_without_stringifying() -> None:
    HostileText.touched = 0

    assert _is_only_filetype_tags(["file_seen", HostileText()]) is False

    assert HostileText.touched == 0


def test_binary_failover_rejects_hostile_tag_container_without_bool_or_iter() -> None:
    HostileTags.touched = 0
    tags: list[str] = []

    assert should_binary_failover("unknown", "unknown", {"magic_stage": "unknown", "magic_type": "unknown", "ext": ".bin"}, [], HostileTags()) is True

    assert HostileTags.touched == 0
    assert tags == []


def test_binary_failover_rejects_hostile_identity_value_before_str_repr_format() -> None:
    HostileText.touched = 0
    tags: list[str] = []

    assert should_binary_failover("unknown", "unknown", {"magic_stage": "unknown", "magic_type": "renpy_rpyc", "ext": HostileText()}, [], tags) is True

    assert HostileText.touched == 0
    assert "binary_failover_identity_malformed" in tags
    assert "binary_failover_final_json_must_record" in tags
    assert "scanner_failure_evidence:binary:should_binary_failover_renpy_identity" in tags


def test_binary_failover_rejects_hostile_identity_key_without_key_comparison_hook() -> None:
    HostileKey.touched = 0
    tags: list[str] = []
    identity = {HostileKey(): ".rpa", "magic_stage": "unknown", "magic_type": "renpy_rpyc"}

    assert should_binary_failover("unknown", "unknown", identity, [], tags) is True

    assert HostileKey.touched == 0
    assert "binary_failover_identity_malformed" in tags
    assert "scanner_failure_evidence:binary:should_binary_failover_magic_stage" in tags


def test_binary_failover_policy_rejects_hostile_renpy_extension_without_hooks() -> None:
    HostileText.touched = 0

    with pytest.raises(TypeError):
        renpy_container_without_payload_evidence({"ext": HostileText(), "magic_type": "renpy_rpyc"}, {"file_seen"})

    assert HostileText.touched == 0


def test_binary_failover_modules_do_not_reintroduce_raw_boundary_conversions() -> None:
    for filename in ("Virus_Scan/scanners/binary_failover.py", "Virus_Scan/scanners/binary_failover_policy.py"):
        source = Path(filename).read_text(encoding="utf-8")
        tree = ast.parse(source)
        raw_str_calls = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "str"
        ]
        assert raw_str_calls == [], (filename, raw_str_calls)
        assert "tags or []" not in source
        assert "final_tags or []" not in source
        assert "str(identity.get" not in source
        assert "str(tag)" not in source
