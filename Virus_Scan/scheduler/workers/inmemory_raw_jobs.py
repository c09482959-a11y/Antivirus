"""Job execution ownership for in-memory raw scheduler enrichment."""
from __future__ import annotations

from concurrent.futures import as_completed
from typing import Mapping


def execute_inmemory_raw_jobs(plan: object, *, deps: object) -> list[dict[str, object]]:
    """Execute planned in-memory raw jobs and preserve degraded job evidence."""
    raw_results: list[dict[str, object]] = []

    def run_job(job: Mapping[str, object]) -> dict[str, object]:
        if deps.now() > plan.deadline:
            return {"ok": False, "error": "inmemory raw timeout before start", "collector": job.get("collector"), "file_id": plan.file_id}
        result = deps.execute_stage_job(dict(job))
        return result if isinstance(result, dict) else {"ok": False, "error": "inmemory raw non-dict result", "collector": job.get("collector"), "file_id": plan.file_id}

    if plan.local_workers <= 1:
        for job in plan.jobs:
            if deps.now() > plan.deadline:
                raw_results.append({"ok": False, "error": "inmemory raw timeout", "collector": job.get("collector"), "file_id": plan.file_id})
                break
            raw_results.append(run_job(job))
        return raw_results

    with deps.scheduler_thread_pool(max_workers=plan.local_workers, thread_name_prefix="umige-raw-local") as executor:
        futures = [executor.submit(run_job, job) for job in plan.jobs]
        for future in as_completed(futures):
            try:
                raw_results.append(future.result(timeout=1))
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                deps.record_issue("inmemory_raw_future_failed", exc, fatal=False, extra={"file_id": str(plan.file_id)[:200]})
                raw_results.append({
                    "ok": False,
                    "error": str(exc),
                    "file_id": plan.file_id,
                    "collector": "inmemory_future",
                    "tags": list(deps.scanner_degraded_tags()),
                })
            if deps.now() > plan.deadline:
                break
    return raw_results
