from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file, read_python_file


import ast
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from Virus_Scan.contracts.result_record import (
    is_passive_fast_asset_result,
    normalize_result_record,
    result_is_cache_reusable,
    validate_result_collection_invariants,
    validate_result_record_invariants,
)


class HostileValue:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    @classmethod
    def touch(cls) -> None:
        cls.touched += 1
        raise AssertionError("hostile hook was invoked")

    def __bool__(self) -> bool:
        self.touch()

    def __str__(self) -> str:
        self.touch()

    def __repr__(self) -> str:
        self.touch()

    def __len__(self) -> int:
        self.touch()

    def __iter__(self):
        self.touch()

    def __eq__(self, other: object) -> bool:
        self.touch()

    def __float__(self) -> float:
        self.touch()

    def __int__(self) -> int:
        self.touch()

    def __hash__(self) -> int:
        return object.__hash__(self)


class HostileMapping(Mapping):
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    @classmethod
    def touch(cls) -> None:
        cls.touched += 1
        raise AssertionError("hostile mapping hook was invoked")

    def __getitem__(self, key: object) -> object:
        self.touch()

    def __iter__(self):
        self.touch()

    def __len__(self) -> int:
        self.touch()

    def get(self, key: object, default: object = None) -> object:
        self.touch()

    def items(self):
        self.touch()

    def values(self):
        self.touch()

    def __bool__(self) -> bool:
        self.touch()


def test_stage1927_result_record_rejects_hostile_mapping_without_mapping_hooks() -> None:
    HostileMapping.reset()

    with pytest.raises(ValueError, match="owned object"):
        validate_result_record_invariants(HostileMapping(), context="stage1927")

    assert HostileMapping.touched == 0


def test_stage1927_result_record_does_not_count_hostile_evidence_key_as_evidence() -> None:
    hostile_key = HostileValue()
    record = {
        "file": "sample.exe",
        "classification": "malicious",
        "score": 95,
        "model_evidence": {hostile_key: {"probability": 0.7}},
    }
    HostileValue.reset()

    with pytest.raises(ValueError, match="high-risk result missing forensic evidence"):
        validate_result_record_invariants(record, context="stage1927")

    assert HostileValue.touched == 0


def test_stage1927_result_record_rejects_hostile_evidence_value_without_value_hooks() -> None:
    record = {
        "file": "sample.exe",
        "classification": "malicious",
        "score": 95,
        "tags": ["model_evidence"],
        "model_evidence": {"unsafe_value": HostileValue()},
    }
    HostileValue.reset()

    with pytest.raises(ValueError, match="non-json value"):
        validate_result_record_invariants(record, context="stage1927")

    assert HostileValue.touched == 0


def test_stage1927_result_normalization_and_cache_checks_do_not_probe_hostile_truthiness() -> None:
    record: dict[str, Any] = {
        "file": "sample.bin",
        "classification": "clean",
        "tags": [],
        "error": HostileValue(),
    }
    HostileValue.reset()

    normalized = normalize_result_record(record, source="stage1927")

    assert HostileValue.touched == 0
    assert normalized["scan_integrity"]["file_failed"] is True
    assert normalized["learn_eligible"] is False
    assert result_is_cache_reusable(record) is False
    assert HostileValue.touched == 0


def test_stage1927_passive_fast_asset_check_rejects_hostile_scalars_without_hooks() -> None:
    record = {
        "file": "asset.png",
        "classification": HostileValue(),
        "tags": HostileValue(),
        "passive_fast_asset": HostileValue(),
        "fast_asset": HostileValue(),
    }
    HostileValue.reset()

    assert is_passive_fast_asset_result(record) is False
    assert HostileValue.touched == 0


def test_stage1927_result_collection_rejects_hostile_results_container_without_hooks() -> None:
    HostileMapping.reset()

    with pytest.raises(ValueError, match="results must be an object or array"):
        validate_result_collection_invariants({"results": HostileMapping()}, context="stage1927")

    assert HostileMapping.touched == 0


def test_stage1927_result_record_source_closes_largest_overall_rows() -> None:
    source = read_python_file(Path("Virus_Scan/contracts/result_record.py"))
    for forbidden in ("isinstance(", ".items(", ".get(", "str(", "bool("):
        assert forbidden not in source
    tree = parse_python_file(Path("Virus_Scan/contracts/result_record.py"))
    assert not any(isinstance(node, ast.JoinedStr) for node in ast.walk(tree))
