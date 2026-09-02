from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.runtime import resource_priority, stage_budget
from Virus_Scan.scheduler.runtime.stage_budget_tables import stage_budget_failure_evidence


class HostileRuntimeValue:
    str_calls = 0
    bool_calls = 0
    int_calls = 0
    float_calls = 0
    iter_calls = 0

    @classmethod
    def reset(cls) -> None:
        cls.str_calls = 0
        cls.bool_calls = 0
        cls.int_calls = 0
        cls.float_calls = 0
        cls.iter_calls = 0

    def __str__(self) -> str:  # pragma: no cover - must not execute
        type(self).str_calls += 1
        raise AssertionError("hostile __str__ executed")

    def __bool__(self) -> bool:  # pragma: no cover - must not execute
        type(self).bool_calls += 1
        raise AssertionError("hostile __bool__ executed")

    def __int__(self) -> int:  # pragma: no cover - must not execute
        type(self).int_calls += 1
        raise AssertionError("hostile __int__ executed")

    def __float__(self) -> float:  # pragma: no cover - must not execute
        type(self).float_calls += 1
        raise AssertionError("hostile __float__ executed")

    def __iter__(self):  # pragma: no cover - must not execute
        type(self).iter_calls += 1
        raise AssertionError("hostile __iter__ executed")


def _assert_no_hostile_hooks() -> None:
    assert HostileRuntimeValue.str_calls == 0
    assert HostileRuntimeValue.bool_calls == 0
    assert HostileRuntimeValue.int_calls == 0
    assert HostileRuntimeValue.float_calls == 0
    assert HostileRuntimeValue.iter_calls == 0


def test_stage1938_resource_priority_profile_rejects_hostile_values_without_hooks() -> None:
    HostileRuntimeValue.reset()
    hostile = HostileRuntimeValue()

    profile, cfg = resource_priority.apply_resource_priority_profile(hostile, env={})
    snapshot = resource_priority.resource_priority_snapshot(
        hostile,
        env={"UMIGE_RESOURCE_PRIORITY": hostile},
    )

    assert profile == "high"
    assert cfg["process_queue_max_children"] == resource_priority.RESOURCE_PRIORITY_SETTINGS["high"]["process_queue_max_children"]
    assert snapshot["profile"] == "high"
    _assert_no_hostile_hooks()


def test_stage1938_stage_budget_tokens_reject_hostile_cost_without_hooks() -> None:
    HostileRuntimeValue.reset()
    hostile = HostileRuntimeValue()

    tokens, cls = stage_budget.weighted_stage_tokens(
        stage_name=hostile,
        cost={"stage": hostile, "weight": hostile},
    )
    evidence = stage_budget_failure_evidence(hostile, hostile, hostile)

    assert tokens == 1
    assert cls == "generic"
    assert evidence["state"] == "failed"
    assert evidence["context"]["boundary_reasons"]
    _assert_no_hostile_hooks()


def test_stage1938_stage_budget_runtime_sources_have_no_unsafe_primitive_conversions() -> None:
    forbidden = {
        "Virus_Scan/scheduler/runtime/resource_priority.py": (
            "str(priority or",
            "source.get(\"UMIGE_RESOURCE_PRIORITY\"",
            "str(cfg[",
            "env_map.items()",
        ),
        "Virus_Scan/scheduler/runtime/stage_budget.py": (
            "int((c or {})",
            "str(stage_name or",
            "return (1, str(stage_name",
            "report_progress(str(stage",
            "int(inc or 1)",
            "int(bytes_delta or 0)",
        ),
        "Virus_Scan/scheduler/runtime/stage_budget_tables.py": (
            "f\"runtime scheduler {kind_text}",
            "record_stage_budget_failure(evidence, exc)\n        return None",
            "record_stage_budget_failure(evidence)\n        return None",
        ),
        "Virus_Scan/scheduler/runtime/stage_cost.py": (
            "return state.get(f'{stage}:{ext}')",
            "for key in (f'{stage}:{ext}', f'{stage}:')",
        ),
        "Virus_Scan/scheduler/runtime/thread_worker_capacity.py": (
            "return None",
            "fallback",
            "source.get(",
            "str(fallback)",
            "diag = f",
            "fallback=",
        ),
    }
    for file_name, patterns in forbidden.items():
        source = Path(file_name).read_text(encoding="utf-8")
        for pattern in patterns:
            assert pattern not in source, f"{file_name}: {pattern}"
