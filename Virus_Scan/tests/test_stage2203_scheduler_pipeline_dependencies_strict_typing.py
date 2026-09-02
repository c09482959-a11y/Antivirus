from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from Virus_Scan.scheduler.api import runner as public_runner
from Virus_Scan.scheduler.orchestration import scheduler_runner as pipeline
from Virus_Scan.scheduler.orchestration.scheduler_target_planning import SchedulerTargetPlanningResult

TARGET = Path("Virus_Scan/scheduler/orchestration/scheduler_pipeline_dependencies.py")


def test_stage2203_scheduler_pipeline_dependencies_have_no_any_boundary_annotations() -> None:
    source = TARGET.read_text(encoding="utf-8")

    assert "Any" not in source
    assert "EnvironmentGetter" in source
    assert "PartialSchedulerWriter" in source
    assert "TargetPlanner" in source
    assert "SchedulerModeRunner" in source
    assert "PipelineFinalizer" in source


def test_stage2203_scheduler_pipeline_dependencies_remain_explicitly_injectable(tmp_path) -> None:
    calls: list[tuple[str, object]] = []

    def _plan_targets(_request, *, log_error, logging_module) -> SchedulerTargetPlanningResult:
        calls.append(("plan", logging_module.__name__))
        return SchedulerTargetPlanningResult(files=(), total_files=0)

    def _write_partial(**kwargs) -> float:
        calls.append(("partial_force", kwargs["force"]))
        return float(kwargs["last_partial_write"])

    deps = replace(
        pipeline.default_scheduler_pipeline_dependencies(),
        plan_scheduler_targets=_plan_targets,
        write_partial_scheduler_results=_write_partial,
        clear_profile_scoring_snapshot=lambda: calls.append(("clear_profile", True)),
        freeze_profile_scoring_snapshot=lambda: calls.append(("freeze_profile", True)),
        flush_all_persistent_models=lambda force=True: calls.append(("flush", force)),
    )

    result = public_runner.run_pipeline_safe(
        str(tmp_path),
        scheduler="serial",
        max_workers=1,
        dependencies=deps,
    )

    assert result == {}
    assert ("plan", "logging") in calls
    assert ("partial_force", True) in calls
    assert ("clear_profile", True) in calls
