from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.scheduler.ownership.inmemory_live_state import InMemoryLiveSchedulerState
from Virus_Scan.scheduler.workers.spawn import (
    ProcessQueueWorkerSpawnRequest,
    build_process_queue_worker_command,
    spawn_process_queue_worker,
)


class HostileText:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")

    def __format__(self, _spec):
        type(self).touched += 1
        raise RuntimeError("do not format")

    def __fspath__(self):
        type(self).touched += 1
        raise RuntimeError("do not fspath")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")


class HostileNumber:
    touched = 0

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("do not float")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("do not int")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")


class HostileMapping(dict):
    touched = 0

    def items(self):
        type(self).touched += 1
        raise RuntimeError("do not items")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iter")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")


class HostileIterable:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iter")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")


@pytest.fixture(autouse=True)
def reset_hostile_counts():
    for cls in (HostileText, HostileNumber, HostileMapping, HostileIterable):
        cls.touched = 0


def _spawn_request(**overrides):
    data = dict(
        root="root",
        queue_dir="queue",
        output="out.json",
        worker_index=1,
        script_path=Path("scanner.py"),
        python_executable="python",
        env_base={"UMIGE_DEEP_SCAN_MODE": "auto"},
        progress_every=10,
        partial_output_every=0,
        slow_file_warn_sec=1.0,
        per_file_timeout_sec=30.0,
        throttle_sec=0.0,
        strict=False,
        scan_session_manifest_path=Path("scan_session_snapshot.json"),
    )
    data.update(overrides)
    return ProcessQueueWorkerSpawnRequest(**data)


def test_stage1634_worker_spawn_command_rejects_hostile_inputs_without_hooks():
    hostile_text = HostileText()
    hostile_number = HostileNumber()
    request = _spawn_request(
        root=hostile_text,
        queue_dir=hostile_text,
        output=hostile_text,
        script_path=hostile_text,
        python_executable=hostile_text,
        env_base={"UMIGE_DEEP_SCAN_MODE": hostile_text},
        progress_every=hostile_number,
        partial_output_every=hostile_number,
        slow_file_warn_sec=hostile_number,
        per_file_timeout_sec=hostile_number,
        throttle_sec=hostile_number,
        strict=hostile_number,
    )

    command = build_process_queue_worker_command(request)

    assert HostileText.touched == 0
    assert HostileNumber.touched == 0
    assert "<rejected-root>" in command
    assert "<rejected-python_executable>" in command
    assert "<rejected-script_path>" in command


def test_stage1634_worker_spawn_rejects_before_popen_without_hostile_hooks():
    calls: list[object] = []
    request = _spawn_request(root=HostileText(), per_file_timeout_sec=HostileNumber())

    result = spawn_process_queue_worker(
        request,
        subprocess_stdin=lambda: None,
        windows_creationflags=lambda **_kwargs: 0,
        log_error=lambda message: calls.append(message),
        recoverable_exceptions=(RuntimeError,),
    )

    assert result.success is False
    assert result.error == "scheduler_worker_spawn_input_rejected"
    assert result.evidence["scheduler_worker_spawn_rejected"] is True
    assert HostileText.touched == 0
    assert HostileNumber.touched == 0
    assert calls


def test_stage1634_inmemory_live_state_rejects_hostile_constructor_containers_without_hooks():
    state = InMemoryLiveSchedulerState(
        active=HostileMapping({"job": {"state": "active"}}),
        worker_heartbeats=HostileMapping(),
        worker_metrics=HostileMapping(),
        done=HostileIterable(),
        failed=HostileIterable(),
        terminal=HostileIterable(),
        results=HostileMapping(),
        processes=HostileIterable(),
        ewma_state=HostileMapping({"stage": 1.0}),
    )

    assert HostileMapping.touched == 0
    assert HostileIterable.touched == 0
    assert state.active == {}
    assert state.done == set()
    assert state.processes == []
    assert state.ewma_state == {}
    assert state.constructor_rejections


def test_stage1634_inmemory_live_state_copies_nested_mapping_values_without_caller_alias():
    active = {"job": {"tags": ["before"]}}
    state = InMemoryLiveSchedulerState(active=active, ewma_state={"stage": "2.5"})

    active["job"]["tags"].append("after")

    assert state.active["job"]["tags"] == ("before",)
    assert state.ewma_state == {"stage": 2.5}
