"""Binary scanner optional resource telemetry helpers."""

from __future__ import annotations

from ctypes import wintypes
import ctypes
import math
import os
import time

from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS


class _UnavailablePsutilModule:
    """Explicit optional-dependency sentinel for scanner resource telemetry."""

    available = False
    dependency = "psutil"

    def cpu_percent(self, *, interval: object = 0.0) -> object:
        del interval
        raise ImportError("psutil_unavailable")

    def Process(self, pid: object) -> object:
        del pid
        raise ImportError("psutil_unavailable")


try:
    import psutil as _psutil_module
except ImportError:
    psutil: object = _UnavailablePsutilModule()
else:
    psutil = _psutil_module

PROCESS_QUERY_LIMITED_INFORMATION = 4096
PROCESS_QUERY_INFORMATION = 1024


def _exact_non_negative_int(value: object) -> object:
    """Return exact primitive process identifier/count input without hooks."""
    if type(value) is bool:
        return None
    if type(value) is int:
        return value if value >= 0 else None
    if type(value) is str and value.isdecimal():
        parsed = int(value)
        return parsed if parsed >= 0 else None
    return None


def _exact_finite_float(value: object) -> object:
    """Return exact primitive telemetry sample without caller-owned numeric hooks."""
    if type(value) is bool:
        return None
    if type(value) is int or type(value) is float:
        sample = float(value)
        if math.isfinite(sample):
            return sample
    return None


def _win_filetime_to_int(ft: object) -> object:
    high = _exact_non_negative_int(ft.dwHighDateTime)
    low = _exact_non_negative_int(ft.dwLowDateTime)
    if high is None or low is None:
        return 0
    return high << 32 | low


class _PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = (
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    )


def _umige_cpu_percent_sample() -> object:
    """Best-effort CPU load sample with explicit unavailable sentinel."""
    cpu_sample_status = "available"
    try:
        sample = _exact_finite_float(psutil.cpu_percent(interval=0.05))
        return sample if sample is not None else -1.0
    except SCAN_CONTENT_ERRORS:
        cpu_sample_status = "unavailable"
    if os.name == 'nt':
        try:
            idle = wintypes.FILETIME()
            kernel = wintypes.FILETIME()
            user = wintypes.FILETIME()
            if not ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
                return -1.0
            _ = (_win_filetime_to_int(idle), _win_filetime_to_int(kernel), _win_filetime_to_int(user), time.time())
            return -1.0
        except SCAN_CONTENT_ERRORS:
            return -1.0
    if cpu_sample_status == "unavailable" and os.name == 'nt':
        return -1.0
    try:
        load1 = _exact_finite_float(os.getloadavg()[0])
        cpu_count = _exact_non_negative_int(os.cpu_count())
        if load1 is None or cpu_count is None or cpu_count < 1:
            return -1.0
        return max(0.0, min(100.0, load1 / float(cpu_count) * 100.0))
    except (AttributeError, IndexError, OSError):
        return -1.0
    except SCAN_CONTENT_ERRORS:
        return -1.0


def _umige_dynamic_cost_multiplier(stage: object, ext: object = None) -> object:
    """Return scanner-owned default cost multiplier; runtime state is not read here."""
    del stage, ext
    return 1.0


def _umige_process_rss_mb(pid: object = None) -> object:
    """Best-effort per-process RSS/private working set in MB.

    Return ``-1.0`` when the metric is unavailable so scanner telemetry failure
    is not confused with a real zero-memory reading.
    """
    rss_status = "available"
    pid_value = os.getpid() if pid is None else _exact_non_negative_int(pid)
    if pid_value is None:
        return -1.0
    try:
        proc = psutil.Process(pid_value)
        rss = _exact_non_negative_int(proc.memory_info().rss)
        return (float(rss) / (1024.0 * 1024.0)) if rss is not None else -1.0
    except SCAN_CONTENT_ERRORS:
        rss_status = "unavailable"
    try:
        if os.name == 'nt':
            h = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION, False, pid_value)
            if h:
                counters = _PROCESS_MEMORY_COUNTERS()
                setattr(counters, "cb", ctypes.sizeof(counters))
                try:
                    if ctypes.windll.psapi.GetProcessMemoryInfo(h, ctypes.byref(counters), counters.cb):
                        working_set_size = _exact_non_negative_int(counters.WorkingSetSize)
                        return (float(working_set_size) / (1024.0 * 1024.0)) if working_set_size is not None else -1.0
                finally:
                    ctypes.windll.kernel32.CloseHandle(h)
    except SCAN_CONTENT_ERRORS:
        rss_status = "unavailable"
    return -1.0 if rss_status == "unavailable" else -1.0


__all__ = ("_umige_cpu_percent_sample", "_umige_dynamic_cost_multiplier", "_umige_process_rss_mb")
