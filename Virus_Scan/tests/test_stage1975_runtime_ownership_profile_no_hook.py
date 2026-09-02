from __future__ import annotations

import ast
from pathlib import Path

import pytest

from Virus_Scan.runtime.ownership import RuntimeStateOwner
from Virus_Scan.runtime.profile_persistence_state import ProfilePersistenceState
from Virus_Scan.runtime.profile_scoring_state import ProfileScoringState
from Virus_Scan.runtime.provenance import ProvenanceLedger


class _HostileText:
    touched = 0

    def __str__(self) -> str:  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise AssertionError("caller-owned text hook executed")

    def __format__(self, spec: str) -> str:  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise AssertionError("caller-owned format hook executed")


RUNTIME_SOURCES = (
    Path("Virus_Scan/runtime/ownership.py"),
    Path("Virus_Scan/runtime/profile_persistence_state.py"),
    Path("Virus_Scan/runtime/profile_scoring_state.py"),
    Path("Virus_Scan/runtime/provenance.py"),
)


def test_stage1975_runtime_owner_rejects_hostile_text_without_hooks() -> None:
    _HostileText.touched = 0
    owner = RuntimeStateOwner()

    with pytest.raises(ValueError, match="runtime_owner_set_key rejected"):
        owner.set(_HostileText(), {"value": 1})
    with pytest.raises(ValueError, match="runtime_owner_update_namespace rejected"):
        owner.update({"child": 1}, namespace=_HostileText())
    with pytest.raises(ValueError, match="runtime_owner_update_key rejected"):
        owner.update({_HostileText(): 1}, namespace="safe")

    owner.update({"child": {"value": 2}}, namespace="safe")
    assert owner.snapshot()["safe.child"]["value"] == 2
    assert _HostileText.touched == 0


def test_stage1975_profile_persistence_rejects_hostile_text_without_hooks() -> None:
    _HostileText.touched = 0
    state = ProfilePersistenceState()

    with pytest.raises(ValueError, match="profile_engine rejected"):
        state.cache_engine_profile(_HostileText(), {})
    with pytest.raises(ValueError, match="profiles_directory rejected"):
        state.bind_profiles_dir(_HostileText())

    assert _HostileText.touched == 0


def test_stage1975_profile_scoring_rejects_hostile_keys_without_hooks() -> None:
    _HostileText.touched = 0
    state = ProfileScoringState()

    detached = state.freeze({_HostileText(): {"score": 3}})

    assert _HostileText.touched == 0
    assert list(detached) == ["profile_key_0"]
    assert detached["profile_key_0"]["unavailable_reason"] == "invalid_key_type"


def test_stage1975_provenance_ledger_rejects_hostile_keys_without_hooks() -> None:
    _HostileText.touched = 0
    ledger = ProvenanceLedger()

    copied = ledger.append({1: "numeric", "1": "text", _HostileText(): "hostile"})

    assert copied["1"] == "numeric"
    assert copied["1#1"] == "text"
    assert copied["provenance_key_2"]["unavailable_reason"] == "invalid_key_type"
    assert _HostileText.touched == 0


def test_stage1975_runtime_profile_sources_keep_repaired_classes_closed() -> None:
    hits: list[str] = []
    for path in RUNTIME_SOURCES:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr):
                hits.append(str(path) + ":" + str(node.lineno) + ":f-string")
        if path.name == "ownership.py" and "dict.items(" in source:
            hits.append(str(path) + ":dict.items")
    assert hits == []
