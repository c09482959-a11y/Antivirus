"""Stage2636.11004 canonical YARA scan-mode execution selection."""
from __future__ import annotations

from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

import pytest

from Virus_Scan.orchestration.yara_initialization import initialize_yara_from_args
from Virus_Scan.runtime.api import RuntimeContext, release_yara_runtime
from Virus_Scan.runtime.config_state import configure_deep_scan_mode, get_deep_scan_mode
from Virus_Scan.runtime.yara_rules_state import YaraRulesState
from Virus_Scan.scheduler.execution.raw_stage_collector_dispatch import dispatch_raw_stage_collector
from Virus_Scan.scheduler.ownership.raw_stage_job_admission import RawStageJobAdmissionState
from Virus_Scan.scheduler.ownership.raw_stage_job_planning import add_raw_stage_yara_jobs
from Virus_Scan.yara.contracts import YaraRuleLoadResult
from Virus_Scan.yara.execution_policy import (
    YARA_CORE_PACKAGE,
    YARA_EXTENDED_PACKAGE,
    selected_yara_snapshot,
    yara_package_for_scan_mode,
)
from Virus_Scan.yara.loader import YaraLoadAttempt
from Virus_Scan.tests.support.canonical_yara_fixtures import canonical_test_yara_no_match_result


def _unready(reason: str) -> YaraLoadAttempt:
    return YaraLoadAttempt(
        None,
        None,
        None,
        YaraRuleLoadResult(
            state="integrity_failure",
            ready=False,
            total_members=0,
            compiled_members=0,
            failed_members=0,
            acceptance_threshold=0.95,
            failure_samples=(),
            reason=reason,
        ),
        False,
    )


def _args(tmp_path: Path, mode: str) -> Namespace:
    return Namespace(
        no_yara=False,
        no_yaralight=False,
        scheduler="serial",
        deep_scan_mode=mode,
        yara=str(tmp_path / "extended.zip"),
        yaralight=str(tmp_path / "core.zip"),
        yara_config=None,
        yara_force_refresh=False,
        yara_no_download=True,
        yaralight_no_download=True,
        yara_release_api_url=None,
        yara_no_cache=True,
        yara_status=False,
    )


def test_fast_mode_selects_only_core_and_other_modes_select_extended() -> None:
    assert yara_package_for_scan_mode("fast") == YARA_CORE_PACKAGE
    for mode in ("auto", "balanced", "default", "thorough", "deep", "exhaustive"):
        assert yara_package_for_scan_mode(mode) == YARA_EXTENDED_PACKAGE


def test_scan_mode_selection_rejects_hook_bearing_carrier() -> None:
    class HostileMode:
        touched = False

        def __str__(self):  # pragma: no cover - execution is failure
            type(self).touched = True
            raise AssertionError("hook executed")

    with pytest.raises(ValueError, match="yara_scan_mode_rejected"):
        yara_package_for_scan_mode(HostileMode())
    assert HostileMode.touched is False


def test_selected_snapshot_uses_existing_runtime_owner_only() -> None:
    state = YaraRulesState()
    state.set_primary_rules("extended", source_path="extended.zip", loaded_count=1)
    state.set_light_rules("core", True, loaded_count=1)

    assert selected_yara_snapshot(state, scan_mode="fast").rules == "core"
    assert selected_yara_snapshot(state, scan_mode="thorough").rules == "extended"


def test_initializer_loads_only_core_in_fast_mode(tmp_path: Path) -> None:
    calls: list[str] = []

    def full(**_kwargs: object) -> YaraLoadAttempt:
        calls.append("extended")
        return _unready("extended_fixture")

    def light(**_kwargs: object) -> YaraLoadAttempt:
        calls.append("core")
        return _unready("core_fixture")

    try:
        with (
            patch("Virus_Scan.orchestration.yara_initialization.yara_dir", lambda: str(tmp_path / "Yara")),
            patch("Virus_Scan.orchestration.yara_initialization.yara_loader.load_yara_rules", full),
            patch("Virus_Scan.orchestration.yara_initialization.yara_loader.load_yaralight_rules", light),
        ):
            compiled, ready = initialize_yara_from_args(RuntimeContext(), _args(tmp_path, "fast"))
    finally:
        release_yara_runtime()

    assert compiled is None
    assert ready is False
    assert calls == ["core"]


def test_initializer_loads_only_extended_outside_fast_mode(tmp_path: Path) -> None:
    calls: list[str] = []

    def full(**_kwargs: object) -> YaraLoadAttempt:
        calls.append("extended")
        return _unready("extended_fixture")

    def light(**_kwargs: object) -> YaraLoadAttempt:
        calls.append("core")
        return _unready("core_fixture")

    try:
        with (
            patch("Virus_Scan.orchestration.yara_initialization.yara_dir", lambda: str(tmp_path / "Yara")),
            patch("Virus_Scan.orchestration.yara_initialization.yara_loader.load_yara_rules", full),
            patch("Virus_Scan.orchestration.yara_initialization.yara_loader.load_yaralight_rules", light),
        ):
            compiled, ready = initialize_yara_from_args(RuntimeContext(), _args(tmp_path, "thorough"))
    finally:
        release_yara_runtime()

    assert compiled is None
    assert ready is False
    assert calls == ["extended"]


class _PlanningDeps:
    def __init__(self, state: YaraRulesState) -> None:
        self.state = state
        self.suppressed: list[str] = []

    def runtime_value(self, name: str, default: object = None) -> object:
        if name == "RAW_PER_FILE_ACTIVE_CAP":
            return 128
        return default

    def yara_rules_state(self) -> YaraRulesState:
        return self.state

    def yara_parallel_group_count(self, _source: object) -> int:
        return 3

    def retry_max(self, _kind: str) -> int:
        return 0

    def raw_collector_cap(self, _collector: str) -> int:
        return 128

    def raw_chunk_bytes(self) -> int:
        return 16384

    def record_suppressed(self, reason: str, _error: object) -> None:
        self.suppressed.append(reason)


def test_raw_job_planning_uses_core_single_job_only_in_fast_mode(tmp_path: Path) -> None:
    previous = get_deep_scan_mode("auto")
    state = YaraRulesState()
    state.set_primary_rules("extended", source_path="extended.zip", loaded_count=1)
    state.set_light_rules("core", True, loaded_count=1)
    deps = _PlanningDeps(state)
    try:
        configure_deep_scan_mode("fast")
        fast = RawStageJobAdmissionState(tmp_path / "sample", "f", deps, [])
        add_raw_stage_yara_jobs(fast, deps=deps)
        assert [job["collector"] for job in fast.jobs] == ["yara"]

        configure_deep_scan_mode("thorough")
        thorough = RawStageJobAdmissionState(tmp_path / "sample", "f", deps, [])
        add_raw_stage_yara_jobs(thorough, deps=deps)
        assert [job["collector"] for job in thorough.jobs] == ["yara"]
    finally:
        configure_deep_scan_mode(previous)


def test_raw_job_planning_requires_selected_snapshot_readiness_without_fallback(
    tmp_path: Path,
) -> None:
    previous = get_deep_scan_mode("auto")
    try:
        heavy_only = YaraRulesState()
        heavy_only.set_primary_rules(
            "extended", source_path="extended.zip", loaded_count=1,
        )
        configure_deep_scan_mode("fast")
        fast = RawStageJobAdmissionState(
            tmp_path / "fast-sample", "fast", _PlanningDeps(heavy_only), [],
        )
        add_raw_stage_yara_jobs(fast, deps=fast.deps)
        assert fast.jobs == []

        light_only = YaraRulesState()
        light_only.set_light_rules("core", True, loaded_count=1)
        configure_deep_scan_mode("thorough")
        thorough = RawStageJobAdmissionState(
            tmp_path / "thorough-sample", "thorough", _PlanningDeps(light_only), [],
        )
        add_raw_stage_yara_jobs(thorough, deps=thorough.deps)
        assert thorough.jobs == []
    finally:
        configure_deep_scan_mode(previous)


class _DispatchDeps:
    def __init__(self, state: YaraRulesState) -> None:
        self.state = state
        self.selected: object = None
        self.group_loaded = False

    def yara_rules_state(self) -> YaraRulesState:
        return self.state

    def yara_scan_with_optional_zip(self, _path: object, *, compiled_rules: object):
        self.selected = compiled_rules
        return canonical_test_yara_no_match_result()

    def normalize_yara_hits(self, _value: object) -> tuple[object, ...]:
        return ()

    def raw_stage_failure_result(
        self, out: dict[str, object], collector: str, error: Exception, *, stage: str,
    ) -> dict[str, object]:
        out["failure"] = {"collector": collector, "reason": str(error), "stage": stage}
        return out


def test_raw_dispatch_uses_core_and_rejects_heavy_group_in_fast_mode() -> None:
    previous = get_deep_scan_mode("auto")
    state = YaraRulesState()
    state.set_primary_rules("extended", source_path="extended.zip", loaded_count=1)
    state.set_light_rules("core", True, loaded_count=1)
    deps = _DispatchDeps(state)
    try:
        configure_deep_scan_mode("fast")
        output = dispatch_raw_stage_collector(
            job={"collector": "yara"},
            path="sample.bin",
            collector="yara",
            start=0,
            size=0,
            out={},
            deps=deps,
        )
        assert "failure" not in output
        assert deps.selected.rules == "core"

        output = dispatch_raw_stage_collector(
            job={"collector": "yara_group", "group_index": 0, "group_count": 1},
            path="sample.bin",
            collector="yara_group",
            start=0,
            size=0,
            out={},
            deps=deps,
        )
        assert output["failure"]["reason"] == "unknown_global_raw_collector:yara_group"
        assert deps.selected.rules == "core"
    finally:
        configure_deep_scan_mode(previous)
