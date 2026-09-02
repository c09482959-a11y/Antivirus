"""Stage2199 strict typing closure for in-memory timeout sweep orchestration."""
from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Mapping, MutableMapping

from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep import enforce_inmemory_timeout_sweep
from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex

SOURCE = Path("Virus_Scan/scheduler/timeout/inmemory_timeout_sweep.py")
CONTRACT_SOURCE = Path("Virus_Scan/scheduler/timeout/inmemory_timeout_sweep_contracts.py")


class Stage2199Recovery:
    def replace_with_history_transition(
        self,
        _job_id: object,
        record: MutableMapping[str, object],
        _reason: str,
        *,
        pid: object | None = None,
        now: float | None = None,
        action: str = "history",
        extra: Mapping[str, object] | None = None,
    ) -> MutableMapping[str, object]:
        record["stage2199_recovery"] = {"pid": pid, "now": now, "action": action, "extra": extra}
        return record

    def retry_or_fail(self, _job_id: object, _reason: str, *, pid: object | None = None) -> object:
        return {"pid": pid}


class Stage2199HostileRecord:
    touched = 0

    def __iter__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned iteration executed")

    def items(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned items executed")

    def __str__(self) -> str:  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned __str__ executed")


def _heartbeat_ingester(**_kwargs: object) -> object:
    return SimpleNamespace(observed=3, cancel_requested=1)


def _callback(*_args: object, **_kwargs: object) -> object:
    return None


def _start_wait_budget(_record: Mapping[str, object], default: float) -> float:
    return default


def _stage_is_pre_execution(_stage: str) -> bool:
    return False


def _suppressed(_where: str, _exc: BaseException) -> object:
    return None


def test_stage2199_timeout_sweep_exports_no_any_annotations() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    contract_source = CONTRACT_SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    any_names = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.Name) and node.id == "Any"]

    assert any_names == []
    assert "typing import Any" not in source
    assert "Any" not in source
    assert "Callable[...," not in source
    assert "SweepJobRecords" in source
    assert "SweepRecovery" in contract_source
    assert "SweepCallback" in contract_source


def test_stage2199_timeout_sweep_preserves_empty_sweep_result_contract() -> None:
    result = enforce_inmemory_timeout_sweep(
        state_index=InMemorySchedulerStateIndex(),
        job_records={},
        active={},
        terminal=set(),
        worker_heartbeats={},
        worker_metrics={},
        heartbeat_table={},
        heartbeat_flags={},
        read_heartbeat=_callback,
        cancel_job=_callback,
        lifecycle_recorder=_callback,
        heartbeat_ingester=_heartbeat_ingester,
        monotonic_ns=lambda: 2199,
        wall_time=lambda: 2199.0,
        recovery=Stage2199Recovery(),
        max_queued_unstarted=3,
        queued_start_timeout_sec=5.0,
        assigned_start_timeout_sec=5.0,
        heartbeat_stale_sec=5.0,
        progress_stale_sec=5.0,
        base_pf_timeout=5.0,
        cancel_grace_sec=1.0,
        start_wait_budget=_start_wait_budget,
        stage_is_pre_execution=_stage_is_pre_execution,
        update_ewma=_callback,
        ewma_state={},
        record_scheduler_suppressed=_suppressed,
        recoverable_exceptions=(RuntimeError, TypeError, ValueError, OSError, AssertionError),
    )

    assert result.evaluated == 0
    assert result.shared_heartbeats_observed == 3
    assert result.shared_heartbeat_cancel_requests == 1
    assert result.timeout_retry_evidence == ()


def test_stage2199_timeout_sweep_records_malformed_record_without_user_hooks() -> None:
    Stage2199HostileRecord.touched = 0

    state_index = InMemorySchedulerStateIndex()
    state_index.sync_record(2199, {"state": "queued"}, due_at=0.0)
    result = enforce_inmemory_timeout_sweep(
        state_index=state_index,
        job_records={2199: Stage2199HostileRecord()},
        active={},
        terminal=set(),
        worker_heartbeats={},
        worker_metrics={},
        heartbeat_table={},
        heartbeat_flags={},
        read_heartbeat=_callback,
        cancel_job=_callback,
        lifecycle_recorder=_callback,
        heartbeat_ingester=_heartbeat_ingester,
        monotonic_ns=lambda: 2199,
        wall_time=lambda: 2199.0,
        recovery=Stage2199Recovery(),
        max_queued_unstarted=3,
        queued_start_timeout_sec=5.0,
        assigned_start_timeout_sec=5.0,
        heartbeat_stale_sec=5.0,
        progress_stale_sec=5.0,
        base_pf_timeout=5.0,
        cancel_grace_sec=1.0,
        start_wait_budget=_start_wait_budget,
        stage_is_pre_execution=_stage_is_pre_execution,
        update_ewma=_callback,
        ewma_state={},
        record_scheduler_suppressed=_suppressed,
        recoverable_exceptions=(RuntimeError, TypeError, ValueError, OSError, AssertionError),
    )

    assert result.evaluated == 1
    assert len(result.timeout_retry_evidence) == 1
    evidence = result.timeout_retry_evidence[0]
    assert evidence["job_id"] == 2199
    assert evidence["reason"] == "job_record_malformed"
    assert evidence["action"] == "timeout_job_record_malformed"
    assert evidence["error_category"] == "TypeError"
    assert evidence["error_source"] == "inmemory_timeout_sweep.job_records"
    assert Stage2199HostileRecord.touched == 0
