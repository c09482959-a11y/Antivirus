"""Deterministic process-scheduler capacity policy for integration tests.

Semantic integration tests execute inside the long-lived pytest cgroup, whose
unrelated parent/test memory can legitimately consume the production scheduler's
normal 2048 MiB per-worker reserve.  These tests are not capacity-policy tests,
so they use one explicit bounded worker budget while still exercising the real
scheduler memory owner.  Dedicated capacity tests continue to validate the
production default and cgroup fail-closed behavior directly.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
from typing import Iterator, Mapping

PROCESS_SCHEDULER_TEST_WORKER_RSS_SETTING = "UMIGE_INMEMORY_WORKER_RSS_LIMIT_MB"
PROCESS_SCHEDULER_TEST_WORKER_RSS_MB = "512"


def process_scheduler_test_environment(
    base: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return an owned environment with the canonical integration-test budget."""
    environment = {} if base is None else dict(base)
    environment[PROCESS_SCHEDULER_TEST_WORKER_RSS_SETTING] = (
        PROCESS_SCHEDULER_TEST_WORKER_RSS_MB
    )
    return environment


@contextmanager
def process_scheduler_test_capacity() -> Iterator[None]:
    """Temporarily apply the shared integration-test process memory budget."""
    setting = PROCESS_SCHEDULER_TEST_WORKER_RSS_SETTING
    previous = os.environ.get(setting)
    os.environ[setting] = PROCESS_SCHEDULER_TEST_WORKER_RSS_MB
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(setting, None)
        else:
            os.environ[setting] = previous


__all__ = (
    "PROCESS_SCHEDULER_TEST_WORKER_RSS_MB",
    "PROCESS_SCHEDULER_TEST_WORKER_RSS_SETTING",
    "process_scheduler_test_capacity",
    "process_scheduler_test_environment",
)
