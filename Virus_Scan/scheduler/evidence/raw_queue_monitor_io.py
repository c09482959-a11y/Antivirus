"""Bounded raw-queue I/O pressure sampling helpers."""
from __future__ import annotations

import time
from typing import Callable, Mapping, TYPE_CHECKING

from Virus_Scan.scheduler.internal.raw_queue_monitor_no_hook import (
    disk_busy_time,
    env_float,
    env_int,
    queue_dir_path,
)
from Virus_Scan.scheduler.runtime.env_policy import scheduler_environment_snapshot
from Virus_Scan.scheduler.evidence.raw_queue_monitor_support import (
    queue_dir_text,
    safe_queue_names,
)

if TYPE_CHECKING:
    from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import QueueListdirFailure

_PSUTIL_UNAVAILABLE = "psutil unavailable"
_DISK_BUSY_SAMPLE_UNAVAILABLE = "disk busy sample unavailable"


def queue_io_pressure_sample(
    queue_dir: object = None,
    *,
    safe_queue_listdir: Callable[[object], list[str] | QueueListdirFailure],
    report: Callable[..., object],
    psutil_module: object = None,
    environ: Mapping[str, str] | None = None,
    sleep: Callable[[float], object] = time.sleep,
    time_fn: Callable[[], float] = time.time,
) -> dict[str, object]:
    """Best-effort local queue I/O pressure probe with explicit diagnostics."""
    env = scheduler_environment_snapshot(environ)
    sample: dict[str, object] = {
        "latency_ms": 0.0,
        "queue_files": 0,
        "pressure": False,
        "reason": "ok",
    }
    try:
        warn_ms = env_float(
            env,
            "UMIGE_IO_PRESSURE_LATENCY_MS",
            env_float(env, "UMIGE_QUEUE_LATENCY_WARN_SEC", 0.35) * 1000.0,
        )
    except (OSError, TypeError, ValueError, OverflowError) as exc:
        report("io_pressure_warn_config_invalid", exc, fatal=False)
        warn_ms = 150.0
    try:
        file_warn = env_int(env, "UMIGE_IO_PRESSURE_QUEUE_FILES", 15000)
    except (OSError, TypeError, ValueError, OverflowError) as exc:
        report("io_pressure_file_warn_config_invalid", exc, fatal=False)
        file_warn = 5000
    try:
        start = time_fn()
        q = queue_dir_path(queue_dir, report)
        total = 0
        if q is not None:
            for sub in ("pending", "active", "done", "failed", "file_results", "failure_diagnostics"):
                try:
                    total += len(
                        safe_queue_names(
                            q / sub,
                            safe_queue_listdir=safe_queue_listdir,
                            report=report,
                            failure_stage="io_pressure_queue_list_failed",
                            failure_extra={"queue_dir": queue_dir_text(q), "subdir": sub},
                        )
                    )
                except (OSError, RuntimeError, TypeError, ValueError) as exc:
                    report(
                        "io_pressure_queue_count_failed",
                        exc,
                        fatal=False,
                        extra={"queue_dir": queue_dir_text(q), "subdir": sub},
                    )
        sample["queue_files"] = int(total)
        sample["latency_ms"] = float((time_fn() - start) * 1000.0)
        reasons: tuple[str, ...] = ()
        if sample["latency_ms"] >= warn_ms:
            reasons += ("queue_latency",)
        if sample["queue_files"] >= file_warn:
            reasons += ("queue_file_count",)
        try:
            if psutil_module is None:
                raise ImportError(_PSUTIL_UNAVAILABLE)
            dio1 = psutil_module.disk_io_counters()
            t1 = time_fn()
            sleep(0.02)
            dio2 = psutil_module.disk_io_counters()
            dt = max(0.001, time_fn() - t1)
            busy1 = disk_busy_time(dio1)
            busy2 = disk_busy_time(dio2)
            if busy1 is None or busy2 is None:
                raise TypeError(_DISK_BUSY_SAMPLE_UNAVAILABLE)
            busy_pct = max(0.0, min(100.0, (busy2 - busy1) / (dt * 10.0)))
            sample["disk_busy_percent"] = busy_pct
            try:
                disk_warn = env_float(env, "UMIGE_IO_PRESSURE_DISK_BUSY", 88.0)
            except (OSError, TypeError, ValueError, OverflowError) as exc:
                report("io_pressure_disk_warn_config_invalid", exc, fatal=False)
                disk_warn = 92.0
            if busy_pct >= disk_warn:
                reasons += ("disk_busy",)
        except (ImportError, OSError, RuntimeError, TypeError, ValueError, AttributeError) as exc:
            report("io_pressure_psutil_probe_failed", exc, fatal=False)
        sample["pressure"] = bool(reasons)
        sample["reason"] = "+".join(reasons) if reasons else "ok"
    except (OSError, RuntimeError, TypeError, ValueError, OverflowError) as exc:
        report("io_pressure_sample_failed", exc, fatal=False)
        sample["pressure"] = False
        sample["reason"] = "sample_error:%s" % (type(exc).__name__,)
    return sample


__all__ = ("queue_io_pressure_sample",)
