from __future__ import annotations

from pathlib import PurePosixPath
from collections.abc import Mapping
from types import MappingProxyType

import pytest

from Virus_Scan.contracts import library_baseline
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_finite_float,
)
from Virus_Scan.contracts.probabilistic_evidence import correlation_group_summary
from Virus_Scan.contracts.result_record import _validated_evidence_count, degraded_scan_integrity
from Virus_Scan.contracts.work_stage import CAPACITY_CLASSES, capacity_for_stage
from Virus_Scan.scheduler.internal.output_publication import write_worker_output_payload
from Virus_Scan.contracts.yara_hits import (
    YARA_HIT_NORMALIZATION_FAILURE_EVIDENCE,
    normalize_yara_hits,
)


class HostileText(str):
    def __str__(self) -> str:  # pragma: no cover - must never be invoked
        raise AssertionError("caller-owned text hook invoked")


class MappingLikeHostileMro:
    @property
    def __class__(self):  # pragma: no cover - type.__getattribute__ path must avoid this
        raise AssertionError("caller-owned class hook invoked")


class UnsupportedMapping(Mapping):
    def __getitem__(self, key: object) -> object:  # pragma: no cover - must never be called
        raise AssertionError("caller-owned mapping access invoked")

    def __iter__(self):  # pragma: no cover - must never be called
        raise AssertionError("caller-owned mapping iteration invoked")

    def __len__(self) -> int:  # pragma: no cover - must never be called
        raise AssertionError("caller-owned mapping length invoked")


class UnsupportedIterable:
    def __iter__(self):  # pragma: no cover - must not be invoked
        raise AssertionError("caller-owned iterable hook invoked")


def test_stage2080_contracts_exact_path_and_tag_materialization_remain_typed() -> None:
    parts, parts_reason = library_baseline._path_parts_status(PurePosixPath("/RenPy/core.py"))
    name, name_reason = library_baseline._path_name_status(PurePosixPath("/RenPy/core.py"))

    assert parts_reason == ""
    assert parts[-2:] == ("renpy", "core.py")
    assert name_reason == ""
    assert name == "core.py"
    assert library_baseline._safe_tag_iter(("alpha", "beta")) == ("alpha", "beta")


def test_stage2080_contracts_no_hook_numeric_text_subclasses_do_not_call_str() -> None:
    assert no_hook_finite_float(HostileText("2.5"), default=0.0) == (2.5, "")
    assert no_hook_exact_nonnegative_int(HostileText("7"), default=0) == (7, "")


def test_stage2080_contracts_worker_write_failure_is_explicit(tmp_path) -> None:
    blocked_parent = tmp_path / "worker-output-parent"
    blocked_parent.write_text("not a directory", encoding="utf-8")

    assert write_worker_output_payload(str(blocked_parent / "worker.json"), {"score": 1}) is False


def test_stage2080_contracts_projection_records_do_not_narrow_dict_values() -> None:
    degraded = degraded_scan_integrity(error=HostileText("boom"), detail={"stage": "contracts"})

    assert degraded["error"] == "boom"
    assert degraded["detail"] == {"stage": "contracts"}


def test_stage2080_contracts_mapping_like_rejection_is_explicit_without_hook_invocation() -> None:
    assert _validated_evidence_count(MappingProxyType({"x": 1}), context="contracts") == 1

    with pytest.raises(ValueError, match="unsupported mapping"):
        _validated_evidence_count(UnsupportedMapping(), context="contracts")

    with pytest.raises(ValueError, match="non-json value"):
        _validated_evidence_count(MappingLikeHostileMro(), context="contracts")


def test_stage2080_contracts_probability_and_yara_sequences_are_materialized_exactly() -> None:
    assert correlation_group_summary(UnsupportedIterable())["unsupported_probability_evidence"]["degraded"] is True
    assert correlation_group_summary(({"correlation_group": "net", "confidence": 0.5},))["net"]["count"] == 1

    assert normalize_yara_hits(None) == []
    assert normalize_yara_hits(UnsupportedIterable()) == [YARA_HIT_NORMALIZATION_FAILURE_EVIDENCE]


def test_stage2080_contracts_work_stage_capacity_mapping_is_immutable() -> None:
    assert capacity_for_stage("archive").name == "archive"
    assert isinstance(CAPACITY_CLASSES, MappingProxyType)
    with pytest.raises(TypeError):
        CAPACITY_CLASSES["new"] = capacity_for_stage("raw")  # type: ignore[index]
