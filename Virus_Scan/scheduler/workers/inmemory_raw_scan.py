"""Worker-owned in-memory raw enrichment scan boundary.

This module is used only by long-lived in-memory worker file scans, so it lives
under worker ownership instead of execution ownership.
"""
from __future__ import annotations

from Virus_Scan.scheduler.workers.inmemory_raw_failure import inmemory_raw_scan_failure_result, record_inmemory_raw_scan_failure
from Virus_Scan.scheduler.workers.inmemory_raw_finalization import finalize_inmemory_raw_scan_result
from Virus_Scan.scheduler.workers.inmemory_raw_jobs import execute_inmemory_raw_jobs
from Virus_Scan.scheduler.workers.inmemory_raw_plan import build_inmemory_raw_plan
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from Virus_Scan.scheduler.contracts.inmemory_raw import InMemoryRawScanDependencies

_NO_INMEMORY_RAW_PLAN = None


def scan_file_inmemory_raw(
    path: object,
    timeout_sec: object=0,
    pretriage_tags: object=None,
    pretriage_suspicious: object=False,
    pretriage_stage: object=None,
    *,
    deps: InMemoryRawScanDependencies,
) -> object:
    """Run raw enrichment inside the worker process without filesystem queue state."""
    try:
        plan = build_inmemory_raw_plan(
            path=path,
            timeout_sec=timeout_sec,
            pretriage_tags=pretriage_tags,
            pretriage_suspicious=pretriage_suspicious,
            pretriage_stage=pretriage_stage,
            deps=deps,
        )
        if plan is None:
            return _NO_INMEMORY_RAW_PLAN
        raw_results = execute_inmemory_raw_jobs(plan, deps=deps)
        return finalize_inmemory_raw_scan_result(
            path=path,
            pretriage_tags=pretriage_tags,
            raw_results=raw_results,
            plan=plan,
            deps=deps,
        )
    except (OSError, RuntimeError, TypeError, ValueError, UnicodeError) as exc:
        record_inmemory_raw_scan_failure(path=path, exc=exc, deps=deps)
        return inmemory_raw_scan_failure_result(path=path, exc=exc, deps=deps)
