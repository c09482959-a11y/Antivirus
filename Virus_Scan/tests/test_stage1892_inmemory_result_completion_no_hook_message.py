from __future__ import annotations
from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex
from Virus_Scan.tests.support.static_inventory import parse_python_file


import ast
from pathlib import Path

from Virus_Scan.scheduler.evidence.partial_checkpoint_cache import PartialCheckpointCache

from Virus_Scan.scheduler.queue.inmemory_result_completion import complete_inmemory_result_message


class HostileValue:
    touched = 0

    def __str__(self):  # pragma: no cover - proves unsafe text hook use
        type(self).touched += 1
        raise AssertionError("hostile __str__ invoked")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile __repr__ invoked")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile __format__ invoked")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile __bool__ invoked")

    def __int__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile __int__ invoked")

    def __float__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile __float__ invoked")

    def __hash__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile __hash__ invoked")


class HostileDescriptorRecovery:
    completed = 0

    @property
    def record_lifecycle_request(self):  # pragma: no cover
        HostileValue.touched += 1
        raise AssertionError("record_lifecycle_request descriptor invoked")

    @property
    def terminal_transition(self):  # pragma: no cover
        HostileValue.touched += 1
        raise AssertionError("terminal_transition descriptor invoked")


def _call_completion(**overrides):
    record = {"attempt": 0, "started_at": 10.0, "queued_at": 10.0}
    state = {
        "job_records": {1: record},
        "active": {1: object()},
        "terminal": set(),
        "failed": set(),
        "done": set(),
        "results": {},
    }
    state.update(overrides.pop("state", {}))
    kwargs = dict(
        message=("result", 1, "sample.bin", {"queue_failure": False}, 123, 11.0, 0),
        job_records=state["job_records"],
        active=state["active"],
        terminal=state["terminal"],
        failed=state["failed"],
        done=state["done"],
        results=state["results"],
        recovery=overrides.pop("recovery", HostileDescriptorRecovery()),
        state_index=InMemorySchedulerStateIndex(),
        container_root=None,
        routing_evidence_context=None,
        routing_evidence_attacher=lambda **kwargs: kwargs["result"],
        attach_result_evidence=lambda **kwargs: kwargs["result"],
        record_stage_cost_observation=lambda **_kwargs: None,
        publish_partial_results=lambda _request: None,
        partial_output_path=None,
        partial_output_every=0,
        partial_writer=lambda *_args, **_kwargs: None,
        partial_checkpoint_cache=PartialCheckpointCache(),
        log_error=lambda _message: None,
        bulk_scan_maintenance=lambda _completed: None,
        log_bulk_progress=lambda *_args, **_kwargs: None,
        started_at=0.0,
        progress_every=0,
        throttle_sec=0.0,
        result_retainer=lambda _path, result: result,
        derived_cache_writer=lambda _result: False,
        wall_time=lambda: 11.0,
        sleep=lambda _seconds: None,
        recoverable_exceptions=(Exception,),
        suppressed_recorder=lambda *_args: None,
    )
    kwargs.update(overrides)
    return complete_inmemory_result_message(**kwargs), state, record


def test_stage1892_rejects_hostile_job_id_and_attempt_without_hooks() -> None:
    HostileValue.touched = 0

    outcome, state, _record = _call_completion(message=("result", HostileValue(), "p", "ok", 1, 1.0, HostileValue()))

    assert outcome.handled is False
    assert state["active"] == {1: state["active"][1]}
    assert HostileValue.touched == 0


def test_stage1892_rejects_hostile_record_attempt_without_hooks() -> None:
    HostileValue.touched = 0

    outcome, _state, _record = _call_completion(state={"job_records": {1: {"attempt": HostileValue()}}})

    assert outcome.handled is False
    assert HostileValue.touched == 0


def test_stage1892_completion_rejects_hostile_timestamps_and_recovery_descriptors_without_hooks() -> None:
    HostileValue.touched = 0

    outcome, state, record = _call_completion(message=("result", 1, "sample.bin", {"queue_failure": False}, 123, HostileValue(), 0))

    assert outcome.handled is True
    assert record["completion_timestamp_rejected"] == "inmemory_result_timestamp_rejected"
    assert record["record_lifecycle_request_unavailable"] == "unsafe_inmemory_recovery_descriptor_rejected"
    assert record["terminal_transition_unavailable"] == "unsafe_inmemory_recovery_descriptor_rejected"
    assert state["done"] == {1}
    assert HostileValue.touched == 0


def test_stage1892_inmemory_result_completion_source_has_no_hook_materializers() -> None:
    root = Path(__file__).resolve().parents[2]
    source_path = root / "Virus_Scan" / "scheduler" / "queue" / "inmemory_result_completion.py"
    tree = parse_python_file(source_path)
    joined = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)]
    raw_numeric = []
    getattr_calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in {"int", "float", "bool"}:
                raw_numeric.append((node.func.id, node.lineno))
            if isinstance(node.func, ast.Name) and node.func.id == "getattr":
                getattr_calls.append(node.lineno)
    assert joined == []
    assert raw_numeric == []
    assert getattr_calls == []
