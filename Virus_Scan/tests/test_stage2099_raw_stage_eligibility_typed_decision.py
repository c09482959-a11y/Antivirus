from __future__ import annotations

import ast
from pathlib import Path

import pytest

from Virus_Scan.scheduler.ownership.raw_stage_eligibility import (
    RawStageEligibilityDecision,
    global_raw_eligibility_decision,
    global_raw_eligible,
)
from Virus_Scan.tests.support.static_inventory import read_python_file


class HostilePath:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    fspath_calls = 0

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("path text hook must not execute")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("path repr hook must not execute")

    def __format__(self, _spec):
        type(self).format_calls += 1
        raise RuntimeError("path format hook must not execute")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("path truth hook must not execute")

    def __fspath__(self):
        type(self).fspath_calls += 1
        raise RuntimeError("path filesystem hook must not execute")


def _reset_hostile_path() -> None:
    for name in tuple(vars(HostilePath)):
        if name.endswith("_calls"):
            setattr(HostilePath, name, 0)


def _assert_no_hostile_path_hooks() -> None:
    for name, value in vars(HostilePath).items():
        if name.endswith("_calls"):
            assert value == 0, name


def test_stage2099_raw_stage_size_unavailable_is_typed_rejection_without_path_hooks() -> None:
    _reset_hostile_path()
    decision = global_raw_eligibility_decision(
        HostilePath(),
        raw_queue_enabled=lambda: True,
        raw_queue_min_bytes=lambda: 0,
        get_size=lambda _path: (_ for _ in ()).throw(OSError("stat denied")),
        get_scan_extension=lambda _path: ".bin",
        normalize_stage=lambda _ext: "binary",
        runtime_value=lambda *_args: False,
    )

    assert decision == RawStageEligibilityDecision(
        eligible=False,
        reason="raw_queue_file_size_unavailable",
        stage="",
        extension="",
        size=0,
        minimum_size=0,
    )
    assert global_raw_eligible(
        HostilePath(),
        raw_queue_enabled=lambda: True,
        raw_queue_min_bytes=lambda: 0,
        get_size=lambda _path: (_ for _ in ()).throw(OSError("stat denied")),
        get_scan_extension=lambda _path: ".bin",
        normalize_stage=lambda _ext: "binary",
        runtime_value=lambda *_args: False,
    ) is False
    _assert_no_hostile_path_hooks()


def test_stage2099_raw_stage_disabled_and_size_floor_are_replayable_rejections() -> None:
    disabled = global_raw_eligibility_decision(
        "sample.exe",
        raw_queue_enabled=lambda: False,
        raw_queue_min_bytes=lambda: 0,
        get_size=lambda _path: 100,
        get_scan_extension=lambda _path: ".exe",
        normalize_stage=lambda _ext: "binary",
        runtime_value=lambda *_args: False,
    )
    undersized = global_raw_eligibility_decision(
        "sample.exe",
        raw_queue_enabled=lambda: True,
        raw_queue_min_bytes=lambda: 256,
        get_size=lambda _path: 100,
        get_scan_extension=lambda _path: ".exe",
        normalize_stage=lambda _ext: "binary",
        runtime_value=lambda *_args: False,
    )

    assert disabled.reason == "raw_queue_disabled"
    assert disabled.eligible is False
    assert undersized.reason == "raw_queue_file_size_below_minimum"
    assert undersized.size == 100
    assert undersized.minimum_size == 256


def test_stage2099_raw_stage_rpa_and_stage_exclusions_are_typed_rejections() -> None:
    rpa = global_raw_eligibility_decision(
        "archive.rpa",
        raw_queue_enabled=lambda: True,
        raw_queue_min_bytes=lambda: 0,
        get_size=lambda _path: 100,
        get_scan_extension=lambda _path: ".rpa",
        normalize_stage=lambda _ext: "archive",
        runtime_value=lambda *_args: False,
    )
    image = global_raw_eligibility_decision(
        "sample.png",
        raw_queue_enabled=lambda: True,
        raw_queue_min_bytes=lambda: 0,
        get_size=lambda _path: 100,
        get_scan_extension=lambda _path: ".png",
        normalize_stage=lambda _ext: "image",
        runtime_value=lambda *_args: False,
    )

    assert rpa.reason == "raw_queue_rpa_global_queue_disabled"
    assert rpa.extension == ".rpa"
    assert image.reason == "raw_queue_stage_not_global_raw_eligible"
    assert image.stage == "image"


def test_stage2099_raw_stage_acceptance_is_typed_and_bool_projection_is_legacy_only() -> None:
    decision = global_raw_eligibility_decision(
        "sample.bin",
        raw_queue_enabled=lambda: True,
        raw_queue_min_bytes=lambda: 10,
        get_size=lambda _path: 100,
        get_scan_extension=lambda _path: ".bin",
        normalize_stage=lambda _ext: "binary",
        runtime_value=lambda *_args: False,
    )

    assert decision == RawStageEligibilityDecision(
        eligible=True,
        reason="raw_queue_eligible",
        stage="binary",
        extension=".bin",
        size=100,
        minimum_size=10,
    )
    assert global_raw_eligible(
        "sample.bin",
        raw_queue_enabled=lambda: True,
        raw_queue_min_bytes=lambda: 10,
        get_size=lambda _path: 100,
        get_scan_extension=lambda _path: ".bin",
        normalize_stage=lambda _ext: "binary",
        runtime_value=lambda *_args: False,
    ) is True


def test_stage2099_raw_stage_invalid_stage_still_fails_closed_without_defaulting() -> None:
    with pytest.raises(ValueError, match="raw_queue_stage_rejected"):
        global_raw_eligibility_decision(
            "sample.bin",
            effective_stage=HostilePath(),
            raw_queue_enabled=lambda: True,
            raw_queue_min_bytes=lambda: 0,
            get_size=lambda _path: 100,
            get_scan_extension=lambda _path: ".bin",
            normalize_stage=lambda _ext: "binary",
            runtime_value=lambda *_args: False,
        )


def test_stage2099_raw_stage_source_uses_typed_decisions_not_literal_false_returns() -> None:
    source = read_python_file(Path("Virus_Scan/scheduler/ownership/raw_stage_eligibility.py"))
    tree = ast.parse(source)
    literal_false_returns: list[int] = []
    literal_none_returns: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Constant):
            if node.value.value is False:
                literal_false_returns.append(node.lineno)
            if node.value.value is None:
                literal_none_returns.append(node.lineno)

    assert literal_false_returns == []
    assert literal_none_returns == []
    assert "RawStageEligibilityDecision.rejected" in source
    assert "global_raw_eligibility_decision(" in source
