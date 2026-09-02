import ast
from pathlib import Path
from typing import Iterator

from Virus_Scan.scheduler.runtime.execution_memory_capacity import UNBOUNDED_EXECUTION_MEMORY
from Virus_Scan.scheduler.timeout.process_queue_monitor_policy import process_queue_monitor_policy

from Virus_Scan.scheduler.runtime.process_queue_runtime_policy import (
    compute_process_queue_child_capacity,
    elastic_process_queue_enabled,
    elastic_process_queue_min_workers,
    process_queue_dynamic_feed_enabled,
    process_queue_launch_delay,
    process_queue_respawn_delay,
)
from Virus_Scan.scheduler.runtime.process_worker_capacity import (
    default_filesystem_queue_workers,
    default_process_scheduler_workers,
    process_queue_is_child_shard,
)
from Virus_Scan.scheduler.queue.feed_policy import (
    build_process_queue_feed_policy,
    decide_process_queue_feed,
    initial_file_feed_buffer,
)
from Virus_Scan.scheduler.runtime.writable_paths import create_process_queue_runtime_dirs

RECOVERABLE = (OSError, ValueError, TypeError, RuntimeError)


def test_process_queue_capacity_and_scheduler_defaults_are_immutable_decisions():
    cap = compute_process_queue_child_capacity(
        requested_process_count=4,
        file_count=100,
        cpu_count=8,
        env={"UMIGE_PROCESS_QUEUE_MAX_CHILDREN": "32"},
        recoverable_exceptions=RECOVERABLE,
        memory_snapshot=UNBOUNDED_EXECUTION_MEMORY,
    )
    assert cap.requested == 4
    assert cap.cpu_fill_cap == 32
    assert cap.process_count == 32
    assert default_process_scheduler_workers(env={"UMIGE_PROCESS_QUEUE_MAX_CHILDREN": "16"}, cpu_count=8, recoverable_exceptions=RECOVERABLE, memory_snapshot=UNBOUNDED_EXECUTION_MEMORY) == 16
    assert default_filesystem_queue_workers(cpu_count=128, env={}, memory_snapshot=UNBOUNDED_EXECUTION_MEMORY) == 32


def test_process_queue_env_policy_parsing_is_explicit_and_preserves_defaults():
    assert process_queue_dynamic_feed_enabled({}, RECOVERABLE) is True
    assert process_queue_dynamic_feed_enabled({"UMIGE_DYNAMIC_QUEUE_FEED": "0"}, RECOVERABLE) is False
    assert elastic_process_queue_enabled({}, RECOVERABLE) is True
    assert elastic_process_queue_min_workers(env={"UMIGE_ELASTIC_MIN_WORKERS": "99"}, requested_process_count=4, process_count=8, recoverable_exceptions=RECOVERABLE) == 8
    assert process_queue_launch_delay({}, RECOVERABLE) == 0.03
    assert process_queue_respawn_delay({}, RECOVERABLE) == 0.01
    assert process_queue_is_child_shard({"UMIGE_PROCESS_SHARD": "1"}) is True


class _HookBomb:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def _hit(self, name: str):
        self.calls.append(name)
        raise AssertionError(name)

    def __bool__(self):
        return self._hit("__bool__")

    def __float__(self):
        return self._hit("__float__")

    def __format__(self, _spec):
        return self._hit("__format__")

    def __int__(self):
        return self._hit("__int__")

    def __iter__(self) -> Iterator[object]:
        return self._hit("__iter__")

    def __repr__(self):
        return self._hit("__repr__")

    def __str__(self):
        return self._hit("__str__")


def test_process_queue_launch_and_respawn_delays_reject_hostile_env_values_without_hooks():
    hostile = _HookBomb()
    env = {
        "UMIGE_PROCESS_QUEUE_LAUNCH_DELAY": hostile,
        "UMIGE_PROCESS_QUEUE_RESPAWN_DELAY": hostile,
    }

    assert process_queue_launch_delay(env, RECOVERABLE) == 0.03
    assert process_queue_respawn_delay(env, RECOVERABLE) == 0.01
    assert hostile.calls == []


def test_process_queue_capacity_and_min_workers_reject_hostile_numeric_hooks():
    hostile = _HookBomb()

    cap = compute_process_queue_child_capacity(
        requested_process_count=hostile,
        file_count=hostile,
        cpu_count=hostile,
        env={},
        recoverable_exceptions=RECOVERABLE,
        memory_snapshot=UNBOUNDED_EXECUTION_MEMORY,
    )
    min_workers = elastic_process_queue_min_workers(
        env={},
        requested_process_count=hostile,
        process_count=hostile,
        recoverable_exceptions=RECOVERABLE,
    )

    assert cap.requested == 1
    assert cap.default_cpu_fill_cap == 8
    assert cap.process_count == 1
    assert min_workers == 1
    assert hostile.calls == []


def test_process_queue_runtime_policy_architecture_uses_scheduler_numeric_parsers():
    source = (
        Path(__file__).resolve().parents[1]
        / "scheduler"
        / "runtime"
        / "process_queue_runtime_policy.py"
    ).read_text()
    tree = ast.parse(source)
    checked = {
        "compute_process_queue_child_capacity",
        "elastic_process_queue_min_workers",
        "process_queue_launch_delay",
        "process_queue_respawn_delay",
    }
    violations: list[tuple[str, int, str]] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in checked:
            for child in ast.walk(node):
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id in {"int", "float"}:
                    violations.append((node.name, child.lineno, child.func.id))
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) and child.func.attr == "get":
                    violations.append((node.name, child.lineno, "get"))
    assert violations == []


def test_monitor_policy_owns_timeout_and_stall_bounds():
    policy = process_queue_monitor_policy(env={}, configured_per_file_timeout_sec=20, recoverable_exceptions=RECOVERABLE)
    assert policy.monitor_sleep_sec == 1.0
    assert policy.per_file_timeout_sec == 30.0
    assert policy.progress_stall_sec == 300.0
    assert policy.idle_grace_sec == 45.0
    assert policy.monitor_heartbeat_sec == 30.0


def test_feed_policy_owns_pending_lane_capacity_without_raw_backlog_starvation():
    policy = build_process_queue_feed_policy(
        {"UMIGE_DYNAMIC_QUEUE_PENDING_MULTIPLIER": "2", "UMIGE_DYNAMIC_QUEUE_MIN_PENDING": "10"},
        target_workers=8,
        recoverable_exceptions=RECOVERABLE,
    )
    assert initial_file_feed_buffer(4, 8, policy) == 40
    decision = decide_process_queue_feed(
        target_workers=8,
        file_active_count=40,
        file_pending_count=2,
        io_pressure=True,
        policy=policy,
    )
    assert decision.feed_capacity > 0


def test_runtime_dirs_are_created_under_explicit_runtime_root(tmp_path):
    dirs = create_process_queue_runtime_dirs(runtime_temp_dir=lambda: tmp_path)
    assert dirs.temp_root == tmp_path
    assert dirs.work_queue_root == tmp_path / "work_queue"
    assert dirs.run_dir.parent == dirs.work_queue_root
    assert dirs.queue_dir == dirs.run_dir / "queue"
    assert dirs.outputs_dir.exists()


def test_runtime_dirs_honor_explicit_work_queue_root_under_temp(tmp_path):
    temp_root = tmp_path / "Temp"
    work_queue_root = temp_root / "custom_queue_root"

    dirs = create_process_queue_runtime_dirs(
        runtime_temp_dir=lambda: temp_root,
        runtime_work_queue_dir=lambda: work_queue_root,
    )

    assert dirs.temp_root == temp_root
    assert dirs.work_queue_root == work_queue_root
    assert dirs.run_dir.parent == work_queue_root
    assert dirs.queue_dir.parent == dirs.run_dir
    assert not (tmp_path / "pending").exists()
    assert not (tmp_path / "active").exists()
    assert not (tmp_path / "done").exists()
    assert not (tmp_path / "failed").exists()
