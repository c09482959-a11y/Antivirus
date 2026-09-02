"""Workload-separated queue classification and immutable planning ownership.

Scheduler planning classifies each collected target exactly once. Summary,
interleave, and weighted-fair ordering consume the same immutable classification
records rather than reopening a target at each planning boundary.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from types import MappingProxyType
from typing import Iterable, Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.runtime.api import StageConcurrencyLimits, queue_cost
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_filesystem_path,
    scheduler_path_text,
)
from Virus_Scan.scheduler.queue.workload_classification_rules import (
    WORKLOAD_EXTENSION_ITEMS,
    classify_workload_from_rules,
)


WORKLOAD_EXTENSIONS = MappingProxyType(dict(WORKLOAD_EXTENSION_ITEMS))
_WORKLOAD_LANES = ("archive", "dotnet", "yara", "image", "raw", "script", "generic")


def classify_workload(
    path: str | os.PathLike[str] | None = None,
    *,
    stage: str | None = None,
    tags: Iterable[str] | None = None,
) -> str:
    """Return the canonical scheduler workload for one target or stage."""

    def path_extension_context(
        path_value: str | os.PathLike[str] | None,
    ) -> tuple[str, str, str]:
        filesystem_path, path_reason = scheduler_filesystem_path(path_value)
        if path_reason != "" or filesystem_path == "":
            return "", path_reason, filesystem_path
        path_text, text_reason = scheduler_path_text(filesystem_path)
        if text_reason != "":
            return "", path_reason, filesystem_path
        return os.path.splitext(path_text)[1].lower(), path_reason, filesystem_path

    return classify_workload_from_rules(
        path,
        stage=stage,
        tags=tags,
        path_extension_context=path_extension_context,
    )


@dataclass(frozen=True, slots=True)
class WorkloadClassifiedTarget:
    """One target and its single planning-generation workload decision."""

    path: object
    workload: str
    filesystem_path: str
    path_rejected: bool


@dataclass(frozen=True, slots=True)
class WorkloadClassificationPlan:
    """Immutable classifications for one collected scheduler target generation."""

    targets: tuple[WorkloadClassifiedTarget, ...]

    def __post_init__(self) -> None:
        if type(self.targets) is not tuple:
            raise TypeError("workload_classification_targets_tuple_required")
        for target in self.targets:
            if type(target) is not WorkloadClassifiedTarget:
                raise TypeError("workload_classified_target_required")


def build_workload_classification_plan(
    paths: Iterable[object] | None,
) -> WorkloadClassificationPlan:
    """Classify each target exactly once for one scheduler planning generation."""
    targets: list[WorkloadClassifiedTarget] = []
    for path in no_hook_sequence_items(paths):
        workload = classify_workload(path)
        if workload == "media":
            workload = "image"
        if workload not in _WORKLOAD_LANES:
            workload = "generic"
        filesystem_path, path_reason = scheduler_filesystem_path(path)
        targets.append(
            WorkloadClassifiedTarget(
                path=path,
                workload=workload,
                filesystem_path=filesystem_path if path_reason == "" else "",
                path_rejected=path_reason != "" or filesystem_path == "",
            )
        )
    return WorkloadClassificationPlan(tuple(targets))


@dataclass(frozen=True)
class WorkloadQueuePlan:
    limits: StageConcurrencyLimits

    @classmethod
    def from_env(cls) -> "WorkloadQueuePlan":
        return cls(StageConcurrencyLimits.from_env())

    def as_dict(self) -> Mapping[str, int]:
        return immutable_mapping(self.limits.as_dict())

    def limit_for(self, workload: str) -> int:
        values = self.as_dict()
        if workload == "media":
            workload = "image"
        return max(1, int(values.get(workload) or values.get("generic") or 1))

    def env_mapping(self) -> Mapping[str, str]:
        values = dict(self.limits.env_mapping())
        values["UMIGE_WORKLOAD_SEPARATED_QUEUES"] = "1"
        return immutable_mapping(values)


def workload_plan_summary(plan: WorkloadClassificationPlan) -> Mapping[str, object]:
    """Publish counts and cost from the canonical classification plan."""
    if type(plan) is not WorkloadClassificationPlan:
        raise TypeError("workload_classification_plan_required")
    queue_plan = WorkloadQueuePlan.from_env()
    counts = {lane: 0 for lane in _WORKLOAD_LANES}
    cost_paths: list[str] = []
    rejected_paths = 0
    for target in plan.targets:
        counts[target.workload] += 1
        if target.path_rejected:
            rejected_paths += 1
        else:
            cost_paths.append(target.filesystem_path)
    return immutable_mapping({
        "limits": queue_plan.as_dict(),
        "counts": immutable_mapping(counts),
        "separated": 1,
        "cost": queue_cost(tuple(cost_paths)),
        "path_rejections": rejected_paths,
    })


__all__ = (
    "WORKLOAD_EXTENSIONS",
    "WORKLOAD_EXTENSION_ITEMS",
    "WorkloadClassificationPlan",
    "WorkloadClassifiedTarget",
    "WorkloadQueuePlan",
    "build_workload_classification_plan",
    "classify_workload",
    "workload_plan_summary",
)
