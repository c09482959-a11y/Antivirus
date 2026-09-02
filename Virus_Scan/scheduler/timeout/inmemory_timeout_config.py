"""Immutable in-memory scheduler timeout configuration ownership."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.timeout.inmemory_timeout_settings import (
    base_file_timeout,
    bounded_float_setting,
    bounded_int_setting,
)


@dataclass(frozen=True, slots=True)
class InMemoryTimeoutConfig:
    max_job_retries: int
    base_file_timeout_seconds: int
    queued_start_timeout_seconds: float
    assigned_start_timeout_seconds: float
    heartbeat_stale_seconds: float
    progress_stale_seconds: float
    cancel_grace_seconds: float
    config_evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "config_evidence", immutable_tuple(self.config_evidence))


def build_inmemory_timeout_config(
    environ: Mapping[str, str], *, per_file_timeout_sec: float | None
) -> InMemoryTimeoutConfig:
    """Return bounded timeout values plus evidence for every rejected input."""
    base_timeout, evidence = base_file_timeout(per_file_timeout_sec)
    retries, item_evidence = bounded_int_setting(
        environ,
        name="UMIGE_INMEMORY_MAX_JOB_RETRIES",
        default=5,
        minimum=0,
    )
    evidence += item_evidence
    start_default = float(max(300, base_timeout * 20))
    queued, item_evidence = bounded_float_setting(
        environ,
        name="UMIGE_INMEMORY_QUEUED_START_TIMEOUT_SEC",
        default=start_default,
        minimum=300.0,
    )
    evidence += item_evidence
    assigned, item_evidence = bounded_float_setting(
        environ,
        name="UMIGE_INMEMORY_ASSIGNED_START_TIMEOUT_SEC",
        default=start_default,
        minimum=300.0,
    )
    evidence += item_evidence
    heartbeat_default = float(max(60, base_timeout * 6))
    heartbeat, item_evidence = bounded_float_setting(
        environ,
        name="UMIGE_INMEMORY_HEARTBEAT_STALE_SEC",
        default=heartbeat_default,
        minimum=60.0,
    )
    evidence += item_evidence
    progress_default = float(max(120, base_timeout * 12))
    progress, item_evidence = bounded_float_setting(
        environ,
        name="UMIGE_INMEMORY_PROGRESS_STALE_SEC",
        default=progress_default,
        minimum=120.0,
    )
    evidence += item_evidence
    cancel_grace, item_evidence = bounded_float_setting(
        environ,
        name="UMIGE_INMEMORY_CANCEL_GRACE_SEC",
        default=30.0,
        minimum=30.0,
    )
    evidence += item_evidence
    return InMemoryTimeoutConfig(
        max_job_retries=retries,
        base_file_timeout_seconds=base_timeout,
        queued_start_timeout_seconds=queued,
        assigned_start_timeout_seconds=assigned,
        heartbeat_stale_seconds=heartbeat,
        progress_stale_seconds=progress,
        cancel_grace_seconds=cancel_grace,
        config_evidence=evidence,
    )


__all__ = ("InMemoryTimeoutConfig", "build_inmemory_timeout_config")
