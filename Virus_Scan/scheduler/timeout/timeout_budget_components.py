"""Bounded timeout-budget component assembly."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_mapping_value
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
    scheduler_float,
    scheduler_int,
)
from Virus_Scan.scheduler.ownership.timeout_authority import (
    build_timeout_authority_snapshot,
)
from Virus_Scan.scheduler.timeout.timeout_budget_metric_collection import (
    join_timeout_inspection_error,
    optional_float_timeout_metric,
    optional_int_timeout_metric,
    timeout_file_size,
    timeout_inspection_metrics,
    timeout_method_name,
)
from Virus_Scan.scheduler.timeout.timeout_budget_policy import (
    TimeoutBudgetPolicyOutput,
    TimeoutBudgetPolicyRequest,
    compute_timeout_budget_policy,
)
from Virus_Scan.scheduler.timeout.timeout_budget_workload import (
    configured_timeout_error,
    infer_workload,
    mb,
)


@dataclass(frozen=True, slots=True)
class TimeoutBudgetComponents:
    """Materialized timeout-budget values before public record construction."""

    workload: str
    method: str
    policy_output: TimeoutBudgetPolicyOutput
    file_size: int
    expanded_size: int | None
    archive_member_count: int
    largest_member_size: int | None
    compression_ratio: float | None
    recursion_depth: int
    nested_archive_count: int
    deep_scan: bool
    image_pixels: int | None
    inspection_error: str | None


def _materialize_timeout_metrics(
    metrics: dict[str, object],
) -> tuple[int, int | None, int | None, float | None, int]:
    """Materialize archive metric fields without caller-owned hooks."""
    member_count, _member_reason = scheduler_int(
        scheduler_mapping_value(metrics, "archive_member_count"),
        default=0,
        minimum=0,
        reason="archive_member_count_rejected",
    )
    expanded_size = optional_int_timeout_metric(
        scheduler_mapping_value(metrics, "estimated_uncompressed_size")
    )
    largest_member_size = optional_int_timeout_metric(
        scheduler_mapping_value(metrics, "largest_member_size")
    )
    compression_ratio = optional_float_timeout_metric(
        scheduler_mapping_value(metrics, "compression_ratio")
    )
    nested, _nested_reason = scheduler_int(
        scheduler_mapping_value(metrics, "nested_archive_count"),
        default=0,
        minimum=0,
        reason="nested_archive_count_rejected",
    )
    return member_count, expanded_size, largest_member_size, compression_ratio, nested


def _compute_timeout_budget_policy_output(
    *,
    workload: str,
    file_size: int,
    expanded_size: int | None,
    largest_member_size: int | None,
    member_count: int,
    compression_ratio: float | None,
    depth: int,
    nested: int,
    image_pixels: int | None,
    inspection_error: str | None,
    deep_scan_value: bool,
    configured_floor: float,
    clamp_hard_budget: object,
) -> TimeoutBudgetPolicyOutput:
    """Compute timeout policy output from already materialized metrics."""
    ratio, _ratio_reason = scheduler_float(
        compression_ratio,
        default=0.0,
        minimum=0.0,
        reason="compression_ratio_rejected",
    )
    return compute_timeout_budget_policy(
        TimeoutBudgetPolicyRequest(
            workload=workload,
            file_size_mb=mb(file_size),
            expanded_size_mb=mb(expanded_size),
            largest_member_mb=mb(largest_member_size),
            archive_member_count=member_count,
            compression_ratio=ratio,
            recursion_depth=depth,
            nested_archive_count=nested,
            image_pixels=image_pixels,
            inspection_error=inspection_error,
            deep_scan=deep_scan_value,
            configured_floor=configured_floor,
        ),
        clamp_hard_budget=clamp_hard_budget,
    )


def build_timeout_budget_components(
    path: object,
    *,
    configured_timeout_seconds: float | None,
    workload_class: str | None,
    method: str | None,
    tags: object,
    deep_scan: bool,
    recursion_depth: int,
    file_size_probe: object,
    artifact_read_snapshot: object = None,
    source: str = "compute_timeout_budget",
) -> TimeoutBudgetComponents:
    """Compute bounded timeout-budget inputs for the public record."""
    file_size, file_size_error = timeout_file_size(path, file_size_probe, artifact_read_snapshot)
    workload = infer_workload(path, workload_class, method, tags)
    timeout_authority = build_timeout_authority_snapshot(
        configured_timeout_seconds,
        source=source,
    )
    depth, _depth_reason = scheduler_int(
        recursion_depth,
        default=0,
        minimum=0,
        reason="recursion_depth_rejected",
    )
    inspection_error = join_timeout_inspection_error(
        file_size_error,
        configured_timeout_error(configured_timeout_seconds),
    )
    metrics, image_pixels, inspection_error = timeout_inspection_metrics(
        path=path,
        workload=workload,
        file_size=file_size,
        inspection_error=inspection_error,
        artifact_read_snapshot=artifact_read_snapshot,
    )
    member_count, expanded_size, largest_member_size, compression_ratio, nested = (
        _materialize_timeout_metrics(metrics)
    )
    deep_scan_value = scheduler_bool(
        deep_scan,
        default=False,
        reason="deep_scan_flag_rejected",
    )[0]
    policy_output = _compute_timeout_budget_policy_output(
        workload=workload,
        file_size=file_size,
        expanded_size=expanded_size,
        largest_member_size=largest_member_size,
        member_count=member_count,
        compression_ratio=compression_ratio,
        depth=depth,
        nested=nested,
        image_pixels=image_pixels,
        inspection_error=inspection_error,
        deep_scan_value=deep_scan_value,
        configured_floor=timeout_authority.configured_floor(),
        clamp_hard_budget=timeout_authority.clamp_hard_budget,
    )
    return TimeoutBudgetComponents(
        workload=workload,
        method=timeout_method_name(method, workload),
        policy_output=policy_output,
        file_size=file_size,
        expanded_size=expanded_size,
        archive_member_count=member_count,
        largest_member_size=largest_member_size,
        compression_ratio=compression_ratio,
        recursion_depth=depth,
        nested_archive_count=nested,
        deep_scan=deep_scan_value,
        image_pixels=image_pixels,
        inspection_error=inspection_error,
    )
