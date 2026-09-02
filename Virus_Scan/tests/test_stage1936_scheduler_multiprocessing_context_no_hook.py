from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.runtime import multiprocessing_context, process_queue_runtime_policy
from Virus_Scan.scheduler.runtime.multiprocessing_context import choose_scheduler_start_method


class HostileValue:
    touched: list[str] = []

    @classmethod
    def reset(cls) -> None:
        cls.touched = []

    def __bool__(self):  # pragma: no cover - failure path
        type(self).touched.append("bool")
        raise AssertionError("__bool__ must not be called")

    def __iter__(self):  # pragma: no cover - failure path
        type(self).touched.append("iter")
        raise AssertionError("__iter__ must not be called")

    def __str__(self):  # pragma: no cover - failure path
        type(self).touched.append("str")
        raise AssertionError("__str__ must not be called")

    def __repr__(self):  # pragma: no cover - failure path
        type(self).touched.append("repr")
        raise AssertionError("__repr__ must not be called")

    def __format__(self, spec):  # pragma: no cover - failure path
        type(self).touched.append("format")
        raise AssertionError("__format__ must not be called")


def test_stage1936_choose_scheduler_start_method_rejects_hostile_inputs_without_hooks() -> None:
    HostileValue.reset()
    hostile = HostileValue()

    method = choose_scheduler_start_method(
        preferred=hostile,
        platform_name=hostile,
        available_start_methods=hostile,
    )

    assert method == "spawn"
    assert HostileValue.touched == []


def test_stage1936_choose_scheduler_start_method_filters_non_text_methods_without_hooks() -> None:
    HostileValue.reset()
    hostile = HostileValue()

    method = choose_scheduler_start_method(
        preferred="forkserver",
        platform_name="posix",
        available_start_methods=("fork", hostile, "forkserver", "spawn"),
    )

    assert method == "forkserver"
    assert HostileValue.touched == []


def test_stage1936_multiprocessing_context_source_closes_fallback_and_sentinel_rows() -> None:
    source = Path(multiprocessing_context.__file__).read_text(encoding="utf-8")
    forbidden = (
        "cross-platform fallback",
        "fallback = choose_scheduler_start_method",
        "return mp.get_context(fallback)",
        "return False",
        "str(method)",
        "str(preferred)",
        "str(platform_name)",
    )
    for snippet in forbidden:
        assert snippet not in source


def test_stage1936_process_queue_runtime_policy_source_closes_stale_fallback_rows() -> None:
    source = Path(process_queue_runtime_policy.__file__).read_text(encoding="utf-8")
    forbidden = (
        "fallback=1,",
        "fallback=0,",
        "value = int_env(env, \"UMIGE_ELASTIC_MIN_WORKERS\", default_min_workers, recoverable_exceptions)",
        "default_min_workers",
    )
    for snippet in forbidden:
        assert snippet not in source
