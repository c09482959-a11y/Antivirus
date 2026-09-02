from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

import pytest

from Virus_Scan.runtime.yara_rules_state import YaraRulesState
from Virus_Scan.scheduler.ownership.raw_stage_eligibility import global_raw_eligible
from Virus_Scan.scheduler.ownership.raw_stage_jobs import RawStageJobBuildDependencies, build_raw_stage_jobs
from Virus_Scan.scheduler.ownership.timeout_authority import build_timeout_authority_snapshot
from Virus_Scan.scheduler.queue.admission import classify_workload


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

    def __format__(self, spec):
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


def test_stage1872_raw_stage_size_oserror_fails_closed_after_exception_boundary_without_path_hooks():
    _reset_hostile_path()
    hostile_path = HostilePath()

    result = global_raw_eligible(
        hostile_path,
        raw_queue_enabled=lambda: True,
        raw_queue_min_bytes=lambda: 0,
        get_size=lambda _path: (_ for _ in ()).throw(OSError("stat denied")),
        get_scan_extension=lambda _path: ".bin",
        normalize_stage=lambda _ext: "binary",
        runtime_value=lambda *_args: False,
    )

    assert result is False
    _assert_no_hostile_path_hooks()


def test_stage1872_raw_stage_rejects_hostile_stage_without_text_hooks():
    _reset_hostile_path()
    hostile_stage = HostilePath()

    with pytest.raises(ValueError, match="raw_queue_stage_rejected"):
        global_raw_eligible(
            "sample.bin",
            effective_stage=hostile_stage,
            raw_queue_enabled=lambda: True,
            raw_queue_min_bytes=lambda: 0,
            get_size=lambda _path: 100,
            get_scan_extension=lambda _path: ".bin",
            normalize_stage=lambda _ext: "binary",
            runtime_value=lambda *_args: False,
        )

    _assert_no_hostile_path_hooks()


def test_stage1872_raw_stage_source_has_no_exception_body_sentinel_or_fallback_keywords():
    source_path = Path("Virus_Scan/scheduler/ownership/raw_stage_eligibility.py")
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    sentinel_returns_in_except = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            for child in ast.walk(node):
                if isinstance(child, ast.Return) and isinstance(child.value, ast.Constant):
                    if child.value.value is False:
                        sentinel_returns_in_except.append(child.lineno)

    assert sentinel_returns_in_except == []
    assert "fallback=0" not in source
    assert 'fallback="unknown"' not in source
    assert 'replacement_text="unknown"' not in source


def test_stage1872_raw_stage_jobs_source_uses_no_hook_scalar_boundaries_for_collector_and_job_record():
    source = read_python_file(Path("Virus_Scan/scheduler/ownership/raw_stage_jobs.py"))

    assert 'c = str(collector or "")' not in source
    assert '"file": str(path)' not in source
    assert "int(start or 0)" not in source
    assert "int(size_arg or deps.raw_chunk_bytes())" not in source
    assert "scheduler_path_text(path)" in source
    assert "scheduler_text(collector" in source
    assert "scheduler_int(start" in source


def test_stage1872_raw_stage_jobs_builds_primitive_job_record_with_path_boundary(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ" + b"x" * 128)
    suppressed: list[tuple[str, str]] = []
    deps = RawStageJobBuildDependencies(
        get_scan_extension=lambda _path: ".exe",
        runtime_value=lambda _name, default=None: default,
        raw_collector_cap=lambda _collector: 16,
        raw_chunk_bytes=lambda: 64,
        raw_queue_max_chunks=lambda: 2,
        retry_max=lambda _scope: 1,
        record_suppressed=lambda reason, exc: suppressed.append((reason, type(exc).__name__)),
        yara_rules_state=YaraRulesState,
        yara_parallel_group_count=lambda _source: 1,
        deep_scan_thorough=lambda: False,
    )

    jobs = build_raw_stage_jobs(sample, "fid", "binary", "binary", {}, deps=deps)

    assert jobs
    assert all(type(job["file"]) is str for job in jobs)
    assert all(type(job["collector"]) is str for job in jobs)
    assert all(type(job["start"]) is int for job in jobs)
    assert all(type(job["size"]) is int for job in jobs)
    assert suppressed == []


def test_stage1872_timeout_authority_source_default_is_explicit_no_fallback_keyword():
    _reset_hostile_path()
    snapshot = build_timeout_authority_snapshot(10.0, source=HostilePath())

    assert snapshot.source == "scheduler_request"
    _assert_no_hostile_path_hooks()
    source = read_python_file(Path("Virus_Scan/scheduler/ownership/timeout_authority.py"))
    assert "fallback=" not in source
    assert "replacement_text=" not in source


def test_stage1872_queue_admission_uses_no_hook_stage_and_path_boundaries():
    _reset_hostile_path()
    assert classify_workload(HostilePath(), stage=HostilePath()) == "generic"
    _assert_no_hostile_path_hooks()

    source = read_python_file(Path("Virus_Scan/scheduler/queue/admission.py"))
    assert "replacement_text=" not in source
    assert "fallback=" not in source
    assert "os.fspath(filesystem_path)" not in source
    assert "WORKLOAD_EXTENSIONS.items()" not in source
    assert "WORKLOAD_EXTENSION_ITEMS" in source
    assert "scheduler_path_text(filesystem_path)" in source
