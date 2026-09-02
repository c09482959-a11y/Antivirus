"""Raw queue retry job preparation ownership."""
from __future__ import annotations

from Virus_Scan.scheduler.queue.raw_retry_job_decisions import RawRetryJobDecision, raw_retry_job_decision


def prepare_raw_retry_job(
    job: object,
    result: object,
    *,
    max_retries_default: int = 1,
    now: float | None = None,
) -> dict[str, object] | None:
    """Return a deterministic raw retry job, or None when retry is exhausted/armed."""
    return raw_retry_job_decision(
        job,
        result,
        max_retries_default=max_retries_default,
        now=now,
    ).retry_job


__all__ = ("RawRetryJobDecision", "prepare_raw_retry_job", "raw_retry_job_decision")
