"""Stage 1560 Phase 2 scheduler stage-budget runtime ownership tests."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from Virus_Scan.runtime.api import scheduler_runtime_state
from Virus_Scan.scheduler.runtime import stage_budget
from Virus_Scan.scheduler.runtime import stage_budget_tables


class CountingSemaphore:
    def __init__(self, *, fail_on: int | None = None) -> None:
        self.acquire_calls = 0
        self.release_calls = 0
        self.fail_on = fail_on

    def acquire(self, *args, **kwargs) -> bool:
        self.acquire_calls += 1
        if self.fail_on is not None and self.acquire_calls == self.fail_on:
            raise RuntimeError("stage budget acquire failed")
        return True

    def release(self) -> None:
        self.release_calls += 1


def _reset_stage_tables() -> None:
    scheduler_runtime_state().configure_worker_stage_tables(stage_limits={}, stage_semaphores={})


@pytest.fixture(autouse=True)
def _clean_stage_tables():
    _reset_stage_tables()
    yield
    _reset_stage_tables()


def test_stage1560_stage_budget_reads_runtime_stage_tables() -> None:
    raw_sem = CountingSemaphore()
    generic_sem = CountingSemaphore()
    scheduler_runtime_state().configure_worker_stage_tables(
        stage_limits={"raw": 3, "generic": 1},
        stage_semaphores={"raw": raw_sem, "generic": generic_sem},
    )

    assert stage_budget.stage_semaphore_for_name("raw") is raw_sem
    assert stage_budget.stage_limit_for_name("raw") == 3


def test_stage1560_weighted_acquire_and_release_use_configured_token_count() -> None:
    raw_sem = CountingSemaphore()
    scheduler_runtime_state().configure_worker_stage_tables(
        stage_limits={"raw": 3, "generic": 1},
        stage_semaphores={"raw": raw_sem, "generic": CountingSemaphore()},
    )

    lease = stage_budget.acquire_weighted_stage_budget(cost={"stage": "raw", "weight": 5})
    assert isinstance(lease, stage_budget.SchedulerStageBudgetLease)
    assert len(lease) == 3
    assert raw_sem.acquire_calls == 3

    stage_budget.release_weighted_stage_budget(lease)
    assert raw_sem.release_calls == 3


def test_stage1560_partial_stage_budget_acquire_failure_releases_prior_tokens() -> None:
    raw_sem = CountingSemaphore(fail_on=3)
    scheduler_runtime_state().configure_worker_stage_tables(
        stage_limits={"raw": 3, "generic": 1},
        stage_semaphores={"raw": raw_sem},
    )

    with pytest.raises(RuntimeError):
        stage_budget.acquire_weighted_stage_budget(cost={"stage": "raw", "weight": 3})

    assert raw_sem.acquire_calls == 3
    assert raw_sem.release_calls == 2


def test_stage1560_missing_stage_budget_returns_evidence_lease() -> None:
    recorded: list[tuple[str, dict[str, object]]] = []

    def record(where, exc, *, domain=None, context=None, **kwargs):
        recorded.append((where, dict(context or {})))
        return where

    with patch.object(stage_budget_tables, "record_suppressed_failure", record):
        lease = stage_budget.acquire_weighted_stage_budget(cost={"stage": "raw", "weight": 2})

    assert isinstance(lease, stage_budget.SchedulerStageBudgetLease)
    assert list(lease) == []
    assert lease.evidence
    assert lease.evidence[0]["error_category"] == "stage_budget_unavailable"
    assert any(item[0] == "stage_budget_unavailable" for item in recorded)


def test_stage1560_corrupt_stage_budget_table_emits_scheduler_evidence() -> None:
    recorded: list[tuple[str, dict[str, object]]] = []

    class CorruptRuntimeState:
        def stage_tables_snapshot(self):
            return {"stage_limits": [], "stage_semaphores": []}

    def record(where, exc, *, domain=None, context=None, **kwargs):
        recorded.append((where, dict(context or {})))
        return where

    with (
        patch.object(stage_budget_tables, "scheduler_runtime_state", lambda: CorruptRuntimeState()),
        patch.object(stage_budget_tables, "record_suppressed_failure", record),
    ):
        assert stage_budget.stage_semaphore_for_name("raw") is None
        assert stage_budget.stage_limit_for_name("raw") == 1
    assert any(item[0] == "stage_budget_corrupt" for item in recorded)
