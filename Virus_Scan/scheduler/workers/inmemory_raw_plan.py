"""Planning ownership for in-memory raw scheduler enrichment."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.workers.inmemory_raw_plan_steps import (
    RawPlanStageDecision,
    load_raw_plan_jobs,
    raw_plan_is_requested,
    resolve_raw_plan_capacity,
    resolve_raw_plan_deadline,
    resolve_raw_plan_stage,
)

if TYPE_CHECKING:
    from Virus_Scan.scheduler.contracts.inmemory_raw import InMemoryRawScanDependencies, RawIdentity


@dataclass(frozen=True)
class InMemoryRawPlan:
    identity: RawIdentity
    ext: str
    effective_stage: str
    file_id: str
    jobs: tuple[Mapping[str, object], ...]
    local_workers: int
    deadline: float

    def __post_init__(self) -> None:
        source_jobs = self.jobs if self.jobs is not None else ()
        object.__setattr__(
            self,
            "jobs",
            tuple(immutable_mapping(job) for job in no_hook_sequence_items(source_jobs)),
        )


@dataclass(frozen=True)
class InMemoryRawPlanDecision:
    """Replayable in-memory raw planning decision."""

    plan: InMemoryRawPlan | None
    reason: str


def build_inmemory_raw_plan_decision(
    *,
    path: object,
    timeout_sec: float,
    pretriage_tags: object,
    pretriage_suspicious: bool,
    pretriage_stage: object,
    deps: InMemoryRawScanDependencies,
) -> InMemoryRawPlanDecision:
    """Build the replayable in-memory raw enrichment planning decision."""

    if not raw_plan_is_requested(
        pretriage_suspicious=pretriage_suspicious,
        pretriage_tags=pretriage_tags,
        deps=deps,
    ):
        return InMemoryRawPlanDecision(plan=None, reason="inmemory_raw_plan_not_requested")
    stage = resolve_raw_plan_stage(path=path, pretriage_stage=pretriage_stage, deps=deps)
    if type(stage) is not RawPlanStageDecision:
        return InMemoryRawPlanDecision(plan=None, reason=str(stage))
    file_id = deps.global_raw_file_id(path)
    jobs = load_raw_plan_jobs(path=path, file_id=file_id, stage=stage, deps=deps)
    if type(jobs) is not tuple:
        return InMemoryRawPlanDecision(plan=None, reason=str(jobs))
    capacity = resolve_raw_plan_capacity(jobs=jobs, deps=deps)
    deadline = resolve_raw_plan_deadline(
        timeout_sec=timeout_sec,
        capped_jobs=capacity.capped_jobs,
        deps=deps,
    )
    return InMemoryRawPlanDecision(
        plan=InMemoryRawPlan(
            identity=stage.identity,
            ext=stage.ext,
            effective_stage=stage.effective_stage,
            file_id=file_id,
            jobs=capacity.capped_jobs,
            local_workers=capacity.local_workers,
            deadline=deadline,
        ),
        reason="inmemory_raw_plan_available",
    )

def build_inmemory_raw_plan(
    *,
    path: object,
    timeout_sec: float,
    pretriage_tags: object,
    pretriage_suspicious: bool,
    pretriage_stage: object,
    deps: InMemoryRawScanDependencies,
) -> InMemoryRawPlan | None:
    """Build the immutable in-memory raw enrichment plan for one file."""
    return build_inmemory_raw_plan_decision(
        path=path,
        timeout_sec=timeout_sec,
        pretriage_tags=pretriage_tags,
        pretriage_suspicious=pretriage_suspicious,
        pretriage_stage=pretriage_stage,
        deps=deps,
    ).plan
