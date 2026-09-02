"""Stage2215 current-source proof for remaining scheduler Class-A rows.

The five rows covered here are closed only as source-proven local control,
fail-closed, or replacement-value sentinels.  None of these helpers publish an
ambiguous successful result for a hidden unavailable/error state: caller-owned
objects are rejected without hooks, unknown queue entries are skipped as local
iteration controls, malformed telemetry fails closed to critical pressure, and
invalid worker cleanup/scalar values are bounded before they reach subprocess
or publication boundaries.
"""
from __future__ import annotations

import ast
import signal
from collections.abc import Callable
from pathlib import Path
from types import MappingProxyType
from typing import Any

from Virus_Scan.scheduler.workers import cleanup as cleanup_module
from Virus_Scan.scheduler.orchestration.process_queue_worker_pool_state import _copy_exact_env
from Virus_Scan.scheduler.queue.raw_queue_counts import _queue_name_text, pending_file_jobs
import Virus_Scan.scheduler.runtime.backpressure_memory as backpressure_memory
from Virus_Scan.scheduler.runtime.backpressure_memory import _tuple_float_field, memory_pressure_snapshot
from Virus_Scan.scheduler.runtime.execution_memory_capacity import ExecutionMemorySnapshot
from Virus_Scan.scheduler.workers.cleanup import wait_for_process_queue_worker_exit
from Virus_Scan.scheduler.workers.cleanup_no_hook import cleanup_timeout
from Virus_Scan.scheduler.workers.cleanup_wait_steps import WorkerExitWaitStepContext
from Virus_Scan.scheduler.workers.no_hook_scalars import _float_replacement, worker_float

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _wait_context(
    *,
    worker_idx: object,
    output: object,
    timeout_sec: object,
    report_issue: Callable[..., object],
) -> WorkerExitWaitStepContext:
    return WorkerExitWaitStepContext(
        worker_idx=worker_idx,
        output=output,
        timeout_sec=timeout_sec,
        report_issue=report_issue,
        os_ops=None,
        default_os_ops=cleanup_module.os,
        terminate_signal=signal.SIGTERM,
        kill_signal=getattr(signal, "SIGKILL", signal.SIGTERM),
    )

_STAGE2215_SOURCE_PROOFS: tuple[tuple[str, str, str, str], ...] = (
    (
        "STAGE1945-SCHEDULER-02151",
        "Virus_Scan/scheduler/orchestration/process_queue_worker_pool_state.py",
        "_copy_exact_env",
        "return {}",
    ),
    (
        "STAGE1945-SCHEDULER-03869",
        "Virus_Scan/scheduler/queue/raw_queue_counts.py",
        "_queue_name_text",
        'return ""',
    ),
    (
        "STAGE1945-SCHEDULER-04724",
        "Virus_Scan/scheduler/runtime/backpressure_memory.py",
        "_tuple_float_field",
        "return 0.0",
    ),
    (
        "STAGE1945-SCHEDULER-05678",
        "Virus_Scan/scheduler/workers/cleanup_no_hook.py",
        "cleanup_timeout",
        "return 0.0",
    ),
    (
        "STAGE1945-SCHEDULER-06434",
        "Virus_Scan/scheduler/workers/no_hook_scalars.py",
        "_float_replacement",
        "return 0.0",
    ),
)


def _source_for_symbol(relative_path: str, symbol: str) -> str:
    path = _REPO_ROOT / relative_path
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == symbol:
            return ast.get_source_segment(source, node) or ""
    raise AssertionError(f"{symbol} not found in {relative_path}")


class HookTrap:
    def __iter__(self):  # pragma: no cover - must not be called by no-hook proof
        raise AssertionError("iteration hook was invoked")

    def __len__(self):  # pragma: no cover - must not be called by no-hook proof
        raise AssertionError("len hook was invoked")

    def __bool__(self):  # pragma: no cover - must not be called by no-hook proof
        raise AssertionError("truthiness hook was invoked")

    def __str__(self):  # pragma: no cover - must not be called by no-hook proof
        raise AssertionError("text hook was invoked")


class _WaitCompletesProcess:
    pid = 321

    def __init__(self) -> None:
        self.wait_timeouts: list[float] = []

    def wait(self, *, timeout: float | None = None) -> int:
        assert type(timeout) is float
        self.wait_timeouts.append(timeout)
        return 0

    def poll(self) -> int | None:  # pragma: no cover - not called when wait succeeds
        raise AssertionError("poll should not run after successful wait")

    def terminate(self) -> None:  # pragma: no cover - not called when wait succeeds
        raise AssertionError("terminate should not run after successful wait")

    def kill(self) -> None:  # pragma: no cover - not called when wait succeeds
        raise AssertionError("kill should not run after successful wait")


class _ShortTelemetryProcess:
    def memory_info(self) -> tuple[()]:
        return ()


class _ShortTelemetryPsutil:
    def virtual_memory(self) -> tuple[()]:
        return ()

    def Process(self, _pid: int) -> _ShortTelemetryProcess:  # noqa: N802 - mirrors psutil API
        return _ShortTelemetryProcess()


def test_stage2215_remaining_scheduler_sentinel_rows_still_map_to_current_source() -> None:
    for defect_id, relative_path, symbol, expected_text in _STAGE2215_SOURCE_PROOFS:
        source = _source_for_symbol(relative_path, symbol)
        assert expected_text in source, defect_id


def test_stage2215_worker_pool_env_empty_dict_is_no_hook_local_sanitized_state() -> None:
    assert _copy_exact_env(HookTrap()) == {}
    assert _copy_exact_env({"PATH": "/bin", "DROP_VALUE": 1, 2: "DROP_KEY"}) == {"PATH": "/bin"}


def test_stage2215_raw_queue_name_empty_text_only_skips_one_local_listing_item(tmp_path: Path) -> None:
    pending = tmp_path / "pending"
    active = tmp_path / "active"
    done = tmp_path / "done"
    failed = tmp_path / "failed"
    reports: list[tuple[str, BaseException, dict[str, str] | None]] = []

    def queue_job_dirs(_queue_dir: object) -> tuple[Path, Path, Path, Path]:
        return pending, active, done, failed

    def read_json_file(path: Path, *, default: object) -> dict[str, object]:
        del default
        if path.name == "raw.json":
            return {"job_type": "raw_stage"}
        return {"job_type": "file"}

    def report(marker: str, exc: BaseException, *, fatal: bool = False, extra: dict[str, str] | None = None) -> None:
        del fatal
        reports.append((marker, exc, extra))

    assert _queue_name_text(HookTrap()) == ""
    assert _queue_name_text("scan.json") == "scan.json"
    assert pending_file_jobs(
        tmp_path,
        queue_job_dirs=queue_job_dirs,
        safe_listdir=lambda _path: [HookTrap(), "scan.json", "raw.json", "notes.txt"],
        read_json_file=read_json_file,
        report=report,
    ) == 1
    assert reports == []


def test_stage2215_short_memory_telemetry_tuple_fails_closed_to_critical_pressure() -> None:
    assert _tuple_float_field((), 1) == 0.0
    original_snapshot = backpressure_memory.execution_memory_snapshot
    try:
        backpressure_memory.execution_memory_snapshot = lambda: ExecutionMemorySnapshot(
            "test", 1, 1, 0, 0, True
        )
        snapshot = memory_pressure_snapshot()
    finally:
        backpressure_memory.execution_memory_snapshot = original_snapshot
    assert type(snapshot) is MappingProxyType
    assert snapshot["available_mb"] == 0.0
    assert snapshot["percent"] == 100.0
    assert snapshot["rss_mb"] == 0.0
    assert snapshot["pressure"] == "critical"


def test_stage2215_cleanup_timeout_default_is_bounded_before_process_wait_boundary() -> None:
    proc = _WaitCompletesProcess()
    issues: list[tuple[str, BaseException, dict[str, object] | None]] = []

    result = wait_for_process_queue_worker_exit(
        proc,
        _wait_context(
            worker_idx=4,
            output="out.json",
            timeout_sec=HookTrap(),
            report_issue=lambda marker, exc, *, fatal=False, extra=None: issues.append((marker, exc, extra)),
        ),
    )

    assert cleanup_timeout(HookTrap()) == 0.0
    assert proc.wait_timeouts == [0.0]
    assert result.status == 0
    assert result.timed_out is False
    assert result.failure_markers == ()
    assert issues == []


def test_stage2215_worker_float_replacement_default_is_local_parse_failure_replacement() -> None:
    assert _float_replacement(HookTrap()) == 0.0
    assert worker_float("not-a-float", replacement=HookTrap()) == (0.0, "worker_float_rejected")
    assert worker_float(2, replacement=HookTrap()) == (2.0, "")
    assert worker_float(None, replacement=5.5) == (5.5, "")
