from __future__ import annotations
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.tests.support.static_inventory import read_python_file
import pytest


import ast
from collections.abc import Mapping
from pathlib import Path

from Virus_Scan.detection.scoring.full_analysis.boundaries import (
    full_analysis_float,
    full_analysis_mapping,
    full_analysis_mapping_get,
    full_analysis_sequence,
    full_analysis_text,
)
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.detection.scoring.full_analysis.input_builder import ScoreContextRequest, build_score_context


class HostileIterable:
    touched = 0

    def __iter__(self):  # pragma: no cover - must not execute
        HostileIterable.touched += 1
        raise AssertionError("caller-owned __iter__ executed")


class HostileMappingNoBacking(Mapping):
    touched = 0

    def __getitem__(self, key):  # pragma: no cover - must not execute
        HostileMappingNoBacking.touched += 1
        raise AssertionError("caller-owned __getitem__ executed")

    def __iter__(self):  # pragma: no cover - must not execute
        HostileMappingNoBacking.touched += 1
        raise AssertionError("caller-owned __iter__ executed")

    def __len__(self):  # pragma: no cover - must not execute
        HostileMappingNoBacking.touched += 1
        raise AssertionError("caller-owned __len__ executed")

    def items(self):  # pragma: no cover - must not execute
        HostileMappingNoBacking.touched += 1
        raise AssertionError("caller-owned items executed")

    def get(self, key, default=None):  # pragma: no cover - must not execute
        HostileMappingNoBacking.touched += 1
        raise AssertionError("caller-owned get executed")


class HostileBackedMapping(Mapping):
    touched = 0

    def __init__(self) -> None:
        self._data = {"api_calls": ["CreateFileW"], "score": 17.5}

    def __getitem__(self, key):  # pragma: no cover - must not execute
        HostileBackedMapping.touched += 1
        raise AssertionError("caller-owned __getitem__ executed")

    def __iter__(self):  # pragma: no cover - must not execute
        HostileBackedMapping.touched += 1
        raise AssertionError("caller-owned __iter__ executed")

    def __len__(self):  # pragma: no cover - must not execute
        HostileBackedMapping.touched += 1
        raise AssertionError("caller-owned __len__ executed")

    def items(self):  # pragma: no cover - must not execute
        HostileBackedMapping.touched += 1
        raise AssertionError("caller-owned items executed")

    def get(self, key, default=None):  # pragma: no cover - must not execute
        HostileBackedMapping.touched += 1
        raise AssertionError("caller-owned get executed")


class HostileDictSubclass(dict):
    touched = 0

    def __iter__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned dict subclass iter executed")

    def items(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned dict subclass items executed")

    def keys(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned dict subclass keys executed")

    def values(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned dict subclass values executed")

    def get(self, key, default=None):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned dict subclass get executed")


class HostileListSubclass(list):
    touched = 0

    def __iter__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned list subclass iter executed")

    def __len__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned list subclass len executed")


class HostileText:
    touched = 0

    def __str__(self):  # pragma: no cover - must not execute
        HostileText.touched += 1
        raise AssertionError("caller-owned __str__ executed")

    def __repr__(self):  # pragma: no cover - must not execute
        HostileText.touched += 1
        raise AssertionError("caller-owned __repr__ executed")


class HostileNumber:
    touched = 0

    def __float__(self):  # pragma: no cover - must not execute
        HostileNumber.touched += 1
        raise AssertionError("caller-owned __float__ executed")

    def __int__(self):  # pragma: no cover - must not execute
        HostileNumber.touched += 1
        raise AssertionError("caller-owned __int__ executed")


def _reset() -> None:
    HostileIterable.touched = 0
    HostileMappingNoBacking.touched = 0
    HostileBackedMapping.touched = 0
    HostileDictSubclass.touched = 0
    HostileListSubclass.touched = 0
    HostileText.touched = 0
    HostileNumber.touched = 0


def test_stage1680_full_analysis_boundaries_reject_unknown_hooks_without_execution() -> None:
    _reset()

    sequence = full_analysis_sequence(HostileIterable())
    mapping = full_analysis_mapping(HostileMappingNoBacking())
    missing = full_analysis_mapping_get(HostileMappingNoBacking(), "api_calls", "fallback")
    text = full_analysis_text(HostileText(), default="fallback-text")
    number = full_analysis_float(HostileNumber(), default=4.5)

    assert sequence[0]["unavailable_reason"] == "full_analysis_iterable_rejected"
    assert mapping["unavailable_reason"] == "full_analysis_mapping_rejected"
    assert missing == "fallback"
    assert text == "fallback-text"
    assert number == 4.5
    assert HostileIterable.touched == 0
    assert HostileMappingNoBacking.touched == 0
    assert HostileText.touched == 0
    assert HostileNumber.touched == 0


def test_stage1680_full_analysis_backing_dict_path_preserves_owned_values_without_mapping_hooks() -> None:
    _reset()

    mapping = full_analysis_mapping(HostileBackedMapping())
    api_calls = full_analysis_mapping_get(HostileBackedMapping(), "api_calls", ())

    assert mapping["api_calls"] == ["CreateFileW"]
    assert mapping["score"] == 17.5
    assert api_calls == ["CreateFileW"]
    assert HostileBackedMapping.touched == 0


def test_stage1680_full_analysis_rejects_hookable_builtin_subclasses() -> None:
    _reset()

    mapping = full_analysis_mapping(HostileDictSubclass({"safe": "value"}))
    sequence = full_analysis_sequence(HostileListSubclass(["safe"]))

    assert mapping["unavailable_reason"] == "full_analysis_mapping_rejected"
    assert sequence[0]["unavailable_reason"] == "full_analysis_iterable_rejected"
    assert HostileDictSubclass.touched == 0
    assert HostileListSubclass.touched == 0


def test_stage1680_build_score_context_production_path_rejects_hostile_public_inputs() -> None:
    _reset()

    canonical_tags = normalize_tag_evidence(("process_exec",))
    canonical_chains = evaluate_chain_evidence(tags=canonical_tags)
    with pytest.raises(TypeError, match="score_context_tag_evidence_required"):
        build_score_context(
            ScoreContextRequest(
                attack_mapping_result=unavailable_attack_mapping_fixture(),
                path="game/script.rpy",
                node=None,
                tag_evidence=HostileIterable(),
                chain_evidence=canonical_chains,
                yara_evidence=None,
                prev_stage=None,
                curr_stage=HostileText(),
                ordered_events=HostileIterable(),
                active_profile="renpy",
                failure_evidence=[],
            )
        )

    assert HostileIterable.touched == 0
    assert HostileMappingNoBacking.touched == 0
    assert HostileText.touched == 0


def test_stage1680_full_analysis_boundary_source_removes_hookable_materialization_snippets() -> None:
    source = read_python_file(Path("Virus_Scan/detection/scoring/full_analysis/boundaries.py"))
    tree = ast.parse(source)
    forbidden = (
        "return tuple(dict.items(backing))",
        "return tuple(dict.items(value))",
        "return None",
        'key_text = f"{key_text}#{index}"',
    )
    assert [snippet for snippet in forbidden if snippet in source] == []
    assert [node for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)] == []
