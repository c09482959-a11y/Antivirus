"""Stage2218 scheduler runtime and elastic wrapper/domain-adapter proofs."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scheduler.runtime import process_queue_runtime_policy as runtime_policy
from Virus_Scan.scheduler.workers import process_queue_elastic_no_hook as elastic_no_hook

RECOVERABLE = (OSError, ValueError, TypeError, RuntimeError)


class HostileScalar:
    def __str__(self) -> str:  # pragma: no cover - must never be reached
        raise AssertionError("scheduler adapter called __str__")

    def __repr__(self) -> str:  # pragma: no cover - must never be reached
        raise AssertionError("scheduler adapter called __repr__")

    def __bool__(self) -> bool:  # pragma: no cover - must never be reached
        raise AssertionError("scheduler adapter called __bool__")

    def __int__(self) -> int:  # pragma: no cover - must never be reached
        raise AssertionError("scheduler adapter called __int__")

    def __float__(self) -> float:  # pragma: no cover - must never be reached
        raise AssertionError("scheduler adapter called __float__")

    def __format__(self, _spec: str) -> str:  # pragma: no cover - must never be reached
        raise AssertionError("scheduler adapter called __format__")


class HookedRuntimeError(RuntimeError):
    def __str__(self) -> str:  # pragma: no cover - scheduler_error_detail uses safe base formatting
        raise AssertionError("elastic error adapter called __str__")

    def __repr__(self) -> str:  # pragma: no cover - must never be reached
        raise AssertionError("elastic error adapter called __repr__")


def test_stage2218_process_queue_runtime_policy_binds_env_keys_and_defaults() -> None:
    env = {
        "UMIGE_DYNAMIC_QUEUE_FEED": "0",
        "UMIGE_ELASTIC_QUEUE_SCHEDULER": "disabled",
        "UMIGE_PROCESS_QUEUE_LAUNCH_DELAY": "0.25",
        "UMIGE_PROCESS_QUEUE_RESPAWN_DELAY": "0.5",
    }

    assert runtime_policy.process_queue_dynamic_feed_enabled(env, RECOVERABLE) is False
    assert runtime_policy.elastic_process_queue_enabled(env, RECOVERABLE) is False
    assert runtime_policy.process_queue_launch_delay(env, RECOVERABLE) == 0.25
    assert runtime_policy.process_queue_respawn_delay(env, RECOVERABLE) == 0.5

    source = Path(runtime_policy.__file__).read_text(encoding="utf-8")
    for env_name in (
        "UMIGE_DYNAMIC_QUEUE_FEED",
        "UMIGE_ELASTIC_QUEUE_SCHEDULER",
        "UMIGE_PROCESS_QUEUE_LAUNCH_DELAY",
        "UMIGE_PROCESS_QUEUE_RESPAWN_DELAY",
    ):
        assert env_name in source

    for adapter_name in (
        "process_queue_dynamic_feed_enabled",
        "elastic_process_queue_enabled",
        "process_queue_launch_delay",
        "process_queue_respawn_delay",
    ):
        assert adapter_name in runtime_policy.__all__


def test_stage2218_process_queue_runtime_policy_rejects_hostile_values_without_scalar_hooks() -> None:
    hostile = HostileScalar()
    env = {
        "UMIGE_DYNAMIC_QUEUE_FEED": hostile,
        "UMIGE_ELASTIC_QUEUE_SCHEDULER": hostile,
        "UMIGE_PROCESS_QUEUE_LAUNCH_DELAY": hostile,
        "UMIGE_PROCESS_QUEUE_RESPAWN_DELAY": hostile,
    }

    assert runtime_policy.process_queue_dynamic_feed_enabled(env, RECOVERABLE) is True
    assert runtime_policy.elastic_process_queue_enabled(env, RECOVERABLE) is True
    assert runtime_policy.process_queue_launch_delay(env, RECOVERABLE) == 0.03
    assert runtime_policy.process_queue_respawn_delay(env, RECOVERABLE) == 0.01


def test_stage2218_elastic_no_hook_scalar_adapters_bind_worker_and_scheduler_parsers() -> None:
    hostile = HostileScalar()

    assert elastic_no_hook.elastic_bool("enabled", default=False, reason="stage2218_bool") == (True, "")
    assert elastic_no_hook.elastic_bool(hostile, default=True, reason="stage2218_bool") == (True, "stage2218_bool")
    assert elastic_no_hook.elastic_int("7", replacement=0, minimum=1, maximum=9, reason="stage2218_int") == (7, "")
    assert elastic_no_hook.elastic_int(hostile, replacement=3, minimum=1, maximum=9, reason="stage2218_int") == (3, "stage2218_int")
    assert elastic_no_hook.elastic_float_or_none("2.5", minimum=0.0, reason="stage2218_float") == (2.5, "")
    assert elastic_no_hook.elastic_float_or_none(hostile, minimum=0.0, reason="stage2218_float") == (None, "stage2218_float")

    for adapter_name in (
        "elastic_bool",
        "elastic_int",
        "elastic_float_or_none",
        "elastic_error_category",
    ):
        assert adapter_name in elastic_no_hook.__all__


def test_stage2218_elastic_no_hook_error_adapters_use_type_and_safe_detail_boundaries() -> None:
    plain_error = RuntimeError("plain detail")
    hostile_error = HookedRuntimeError("hidden detail")

    assert elastic_no_hook.elastic_error_category(plain_error) == "RuntimeError"
    assert elastic_no_hook.elastic_error_detail(plain_error) == "plain detail"
    assert elastic_no_hook.elastic_error_category(hostile_error) == "HookedRuntimeError"
    assert (
        elastic_no_hook.elastic_error_detail(hostile_error)
        == "scheduler diagnostic detail unavailable without caller hooks"
    )


def test_stage2218_runtime_and_elastic_adapter_source_boundaries_are_explicit_domain_routes() -> None:
    runtime_source = Path(runtime_policy.__file__).read_text(encoding="utf-8")
    elastic_source = Path(elastic_no_hook.__file__).read_text(encoding="utf-8")

    runtime_tree = ast.parse(runtime_source)
    runtime_functions = {
        node.name: node
        for node in runtime_tree.body
        if isinstance(node, ast.FunctionDef)
    }
    expected_runtime = {
        "process_queue_dynamic_feed_enabled": "bool_env",
        "elastic_process_queue_enabled": "bool_env",
        "process_queue_launch_delay": "float_env",
        "process_queue_respawn_delay": "float_env",
    }
    for adapter_name, canonical_callee in expected_runtime.items():
        calls = {
            child.func.id
            for child in ast.walk(runtime_functions[adapter_name])
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Name)
        }
        assert canonical_callee in calls

    elastic_tree = ast.parse(elastic_source)
    elastic_functions = {
        node.name: node
        for node in elastic_tree.body
        if isinstance(node, ast.FunctionDef)
    }
    expected_elastic = {
        "elastic_bool": "scheduler_bool",
        "elastic_int": "worker_int",
        "elastic_float_or_none": "worker_optional_float",
        "elastic_error_category": "no_hook_type_name",
    }
    for adapter_name, canonical_callee in expected_elastic.items():
        calls = {
            child.func.id
            for child in ast.walk(elastic_functions[adapter_name])
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Name)
        }
        assert canonical_callee in calls
