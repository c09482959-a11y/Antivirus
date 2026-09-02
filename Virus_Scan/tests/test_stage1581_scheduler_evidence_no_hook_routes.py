from __future__ import annotations
from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex

import ast
from collections.abc import Mapping
from pathlib import Path

from Virus_Scan.scheduler.evidence.partial_checkpoint_cache import PartialCheckpointCache
from typing import Any, cast

from Virus_Scan.scheduler.evidence.inmemory_result_timeout import (
    attach_inmemory_result_evidence,
)
from Virus_Scan.scheduler.queue.inmemory_retry_publication import (
    retry_pending_publication_evidence,
)
from Virus_Scan.scheduler.queue.inmemory_result_completion import (
    complete_inmemory_result_message,
)
from Virus_Scan.scheduler.queue.orphan_recovery_action_evidence import (
    OrphanRecoveryActionEvidenceRequest,
    orphan_recovery_action_evidence,
)
from Virus_Scan.scheduler.queue.recovery_contract import (
    build_inmemory_retry_transition,
)
from Virus_Scan.scheduler.queue.retry_callback_evidence import (
    retry_policy_callback_evidence,
)
from Virus_Scan.scheduler.timeout.inmemory_timeout_evidence import (
    timeout_retry_evidence,
)


class HostileSchedulerValue:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise AssertionError("scheduler evidence called __str__")

    def __repr__(self):
        type(self).touched += 1
        raise AssertionError("scheduler evidence called __repr__")

    def __format__(self, _spec):
        type(self).touched += 1
        raise AssertionError("scheduler evidence called __format__")

    def __iter__(self):
        type(self).touched += 1
        raise AssertionError("scheduler evidence called __iter__")

    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("scheduler evidence called __bool__")

    def __len__(self):
        type(self).touched += 1
        raise AssertionError("scheduler evidence called __len__")


class HostileSchedulerMapping(Mapping):
    def __getitem__(self, _key):
        HostileSchedulerValue.touched += 1
        raise AssertionError("scheduler evidence called mapping __getitem__")

    def __iter__(self):
        HostileSchedulerValue.touched += 1
        raise AssertionError("scheduler evidence called mapping __iter__")

    def __len__(self):
        HostileSchedulerValue.touched += 1
        raise AssertionError("scheduler evidence called mapping __len__")


class HostileSchedulerError(Exception):
    def __str__(self):
        HostileSchedulerValue.touched += 1
        raise AssertionError("scheduler evidence stringified exception")

    def __repr__(self):
        HostileSchedulerValue.touched += 1
        raise AssertionError("scheduler evidence repr'd exception")

    def __format__(self, _spec):
        HostileSchedulerValue.touched += 1
        raise AssertionError("scheduler evidence formatted exception")


def test_stage1581_retry_timeout_and_orphan_evidence_do_not_call_hostile_hooks() -> None:
    hostile = HostileSchedulerValue()
    error = HostileSchedulerError("hidden")
    HostileSchedulerValue.touched = 0

    pending = retry_pending_publication_evidence(
        job_id=1,
        generation=2,
        reason=hostile,
        path=hostile,
        error=error,
    ).as_record()
    callback = retry_policy_callback_evidence(
        path=hostile,
        attempt=2,
        callback_name=cast(Any, hostile),
        error=error,
    ).as_record()
    orphan = orphan_recovery_action_evidence(OrphanRecoveryActionEvidenceRequest(
        stage="orphan_recovery",
        action="move",
        source_path=hostile,
        destination_path=hostile,
        job_id=hostile,
        error=error,
        error_source="scheduler.queue.orphan_recovery",
    )).as_record()
    timeout = timeout_retry_evidence(
        job_id=hostile,
        reason=cast(Any, hostile),
        pid=hostile,
        action=cast(Any, hostile),
        attempt=hostile,
        timeout_budget=HostileSchedulerMapping(),
        detail=cast(Any, hostile),
    )

    assert HostileSchedulerValue.touched == 0
    assert "unsupported_retry_reason" in pending["reason"]
    assert "unsupported_retry_path" in pending["file"]
    assert "scheduler diagnostic detail unavailable" in pending["detail"]
    assert "unsupported_retry_callback_name" in callback["callback_name"]
    assert "unsupported_orphan_source_path" in orphan["source_path"]
    assert cast(Mapping[str, Any], timeout["job_id"])["unsupported_scheduler_value"] is True
    assert cast(Mapping[str, Any], timeout["timeout_budget"])["unsupported_scheduler_value"] is True


def test_stage1581_recovery_contract_rejects_hostile_mapping_without_hooks() -> None:
    HostileSchedulerValue.touched = 0

    transition = build_inmemory_retry_transition(
        HostileSchedulerMapping(),
        HostileSchedulerValue(),
        pid=1,
        now=10.0,
    )
    record = transition.as_record()

    assert HostileSchedulerValue.touched == 0
    assert record["scheduler_mapping_unavailable"] is True
    assert cast(Mapping[str, Any], record["evidence"])["unsupported_scheduler_value"] is True
    assert "unsupported_retry_reason" in cast(str, record["retry_pending_reason"])


def test_stage1581_empty_timeout_tags_are_neutral_not_rejected() -> None:
    calls = []

    def attach(enriched, path, **kwargs):
        calls.append((enriched, path, kwargs))
        return enriched

    result = attach_inmemory_result_evidence(
        result={"tags": (), "trusted_benign": False},
        record={
            "last_heartbeat": 10.0,
            "last_progress_time": 10.0,
            "stage": "scan",
            "pid": 7,
        },
        path="sample.bin",
        worker_pid=7,
        container_root="root",
        evidence_context=None,
        routing_evidence_attacher=attach,
        wall_time=lambda: 11.0,
    )

    assert calls[0][2]["tags"] == ()
    assert calls[0][2]["degraded"] is False
    assert "scheduler_timeout_input_rejections" not in result["timeout_evidence"]


def test_stage1581_malformed_parent_result_message_does_not_call_hooks() -> None:
    HostileSchedulerValue.touched = 0
    messages: list[str] = []

    outcome = complete_inmemory_result_message(
        message=HostileSchedulerValue(),
        job_records={},
        active={},
        terminal=set(),
        failed=set(),
        done=set(),
        results={},
        recovery=None,
        state_index=InMemorySchedulerStateIndex(),
        container_root=None,
        routing_evidence_context=None,
        routing_evidence_attacher=lambda *args, **kwargs: None,
        attach_result_evidence=lambda **kwargs: None,
        record_stage_cost_observation=lambda **kwargs: None,
        publish_partial_results=lambda _request: None,
        partial_output_path=None,
        partial_output_every=0,
        partial_writer=lambda *args, **kwargs: None,
        partial_checkpoint_cache=PartialCheckpointCache(),
        log_error=messages.append,
        bulk_scan_maintenance=lambda _completed: None,
        log_bulk_progress=lambda *args, **kwargs: None,
        started_at=0.0,
        progress_every=0,
        throttle_sec=0.0,
        result_retainer=lambda _path, result: result,
        derived_cache_writer=lambda _result: False,
        wall_time=lambda: 0.0,
        sleep=lambda _seconds: None,
        recoverable_exceptions=(RuntimeError, TypeError, ValueError),
        suppressed_recorder=lambda *_args, **_kwargs: None,
    )

    assert outcome.handled is False
    assert HostileSchedulerValue.touched == 0
    assert messages == [
        "in-memory scheduler ignored bad result message: "
        "type=HostileSchedulerValue items=0"
    ]


def test_stage1581_scheduler_evidence_producers_have_no_raw_hook_formatters() -> None:
    root = Path(__file__).resolve().parents[2]
    paths = (
        "Virus_Scan/scheduler/queue/inmemory_retry_publication.py",
        "Virus_Scan/scheduler/queue/inmemory_retry_contracts.py",
        "Virus_Scan/scheduler/queue/inmemory_retry_missing_record.py",
        "Virus_Scan/scheduler/queue/inmemory_retry_failure_result.py",
        "Virus_Scan/scheduler/queue/inmemory_retry_exhaustion_integrity.py",
        "Virus_Scan/scheduler/queue/retry_callback_evidence.py",
        "Virus_Scan/scheduler/queue/retry_integrity_evidence.py",
        "Virus_Scan/scheduler/queue/retry_publication_evidence.py",
        "Virus_Scan/scheduler/queue/orphan_recovery_action_evidence.py",
        "Virus_Scan/scheduler/timeout/inmemory_timeout_evidence.py",
        "Virus_Scan/scheduler/timeout/inmemory_memory_policy.py",
        "Virus_Scan/scheduler/timeout/inmemory_memory_toxicity_evidence.py",
    )
    offenders = []
    for relative in paths:
        path = root / relative
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in {"str", "repr", "format"}:
                    offenders.append(f"{relative}:{node.lineno}:{node.func.id}")

    assert offenders == []
