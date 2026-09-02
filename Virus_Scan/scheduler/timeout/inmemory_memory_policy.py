"""In-memory worker memory policy ownership."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_exception_text,
    scheduler_float,
    scheduler_value_snapshot,
)
from Virus_Scan.scheduler.runtime.execution_memory_capacity import worker_rss_limit_decision
from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name


@dataclass(frozen=True, slots=True)
class InMemoryWorkerMemoryPolicy:
    """Immutable timeout-owned worker memory policy."""

    rss_limit_mb: float
    config_evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "config_evidence", immutable_tuple(self.config_evidence))


def _memory_policy_config_evidence(*, raw_value: object, error: BaseException, default_value: float = 2048.0) -> Mapping[str, object]:
    safe_default_value, _default_reason = scheduler_float(
        default_value,
        default=2048.0,
        minimum=0.0,
        reason="worker_rss_limit_default_rejected",
        non_finite_reason="worker_rss_limit_default_non_finite",
    )
    return MappingProxyType(
        {
            "stage": "inmemory_worker_memory_policy_config",
            "setting": "UMIGE_INMEMORY_WORKER_RSS_LIMIT_MB",
            "raw_value": scheduler_value_snapshot(raw_value, field_name="worker_rss_limit_mb"),
            "default_value": safe_default_value,
            "error_category": no_hook_type_name(error),
            "error_source": "inmemory_memory_policy.build",
            "detail": scheduler_exception_text(error),
            "timeout_failure": True,
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_reproduce": True,
        }
    )


def build_inmemory_worker_memory_policy(environ: Mapping[str, str]) -> InMemoryWorkerMemoryPolicy:
    """Build the immutable worker RSS policy from scheduler runtime configuration."""
    raw_value = environ.get("UMIGE_INMEMORY_WORKER_RSS_LIMIT_MB", "2048")
    evidence: tuple[Mapping[str, object], ...] = ()
    rss_limit_mb, reject_reason = worker_rss_limit_decision(environ)
    if reject_reason:
        evidence = (
            _memory_policy_config_evidence(
                raw_value=raw_value,
                error=ValueError(reject_reason),
            ),
        )
    return InMemoryWorkerMemoryPolicy(rss_limit_mb=rss_limit_mb, config_evidence=evidence)


__all__ = ("InMemoryWorkerMemoryPolicy", "build_inmemory_worker_memory_policy")
