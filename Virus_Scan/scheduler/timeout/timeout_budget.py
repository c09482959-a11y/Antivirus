from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, TYPE_CHECKING

from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_mapping_value
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
    scheduler_float,
    scheduler_int,
    scheduler_text,
)
from Virus_Scan.scheduler.timeout.timeout_budget_components import (
    build_timeout_budget_components,
)
from Virus_Scan.scheduler.timeout.timeout_workload_inspection import archive_metrics, image_pixel_count

if TYPE_CHECKING:
    import os


_TIMEOUT_WORKLOAD_INSPECTION_PUBLIC_CONTRACTS = (archive_metrics, image_pixel_count)


@dataclass(frozen=True, slots=True)
class TimeoutBudget:
    workload_class: str
    method: str
    hard_timeout_seconds: float
    stall_timeout_seconds: float
    heartbeat_stale_seconds: float
    file_size: int
    compressed_size: int | None = None
    estimated_uncompressed_size: int | None = None
    archive_member_count: int | None = None
    largest_member_size: int | None = None
    compression_ratio: float | None = None
    recursion_depth: int = 0
    nested_archive_count: int = 0
    deep_scan: bool = False
    image_pixels: int | None = None
    inspection_error: str | None = None

    def as_evidence(self) -> dict[str, object]:
        workload_class, _workload_reason = scheduler_text(self.workload_class, replacement_text="generic_scan", unsupported_reason="workload_class_rejected")
        method, _method_reason = scheduler_text(self.method, replacement_text=workload_class, unsupported_reason="scan_method_rejected")
        inspection_error, inspection_reason = scheduler_text(self.inspection_error, replacement_text="", unsupported_reason="inspection_error_rejected")
        has_inspection_error = inspection_reason == "" and inspection_error != ""
        return {
            "workload_class": workload_class,
            "scan_method": method,
            "timeout_budget": round(scheduler_float(self.hard_timeout_seconds, default=0.0, minimum=0.0)[0], 3),
            "stall_budget": round(scheduler_float(self.stall_timeout_seconds, default=0.0, minimum=0.0)[0], 3),
            "heartbeat_stale_budget": round(scheduler_float(self.heartbeat_stale_seconds, default=0.0, minimum=0.0)[0], 3),
            "file_size": scheduler_int(self.file_size, default=0, minimum=0)[0],
            "compressed_size": None if self.compressed_size is None else scheduler_int(self.compressed_size, default=0, minimum=0)[0],
            "estimated_uncompressed_size": None if self.estimated_uncompressed_size is None else scheduler_int(self.estimated_uncompressed_size, default=0, minimum=0)[0],
            "archive_member_count": None if self.archive_member_count is None else scheduler_int(self.archive_member_count, default=0, minimum=0)[0],
            "largest_member_size": None if self.largest_member_size is None else scheduler_int(self.largest_member_size, default=0, minimum=0)[0],
            "compression_ratio": None if self.compression_ratio is None else scheduler_float(self.compression_ratio, default=0.0, minimum=0.0)[0],
            "recursion_depth": scheduler_int(self.recursion_depth, default=0, minimum=0)[0],
            "nested_archive_count": scheduler_int(self.nested_archive_count, default=0, minimum=0)[0],
            "deep_scan": scheduler_bool(self.deep_scan, default=False)[0],
            "image_pixels": None if self.image_pixels is None else scheduler_int(self.image_pixels, default=0, minimum=0)[0],
            "inspection_error": inspection_error if has_inspection_error else None,
            "timeout_reason": None,
            "stall_reason": None,
            "final_json_must_record": has_inspection_error,
            "checkpoint_must_record": has_inspection_error,
            "replay_must_reproduce": has_inspection_error,
        }


def compute_timeout_budget(
    path: str | os.PathLike[str] | None,
    *,
    configured_timeout_seconds: float | None = None,
    workload_class: str | None = None,
    method: str | None = None,
    tags: object = None,
    deep_scan: bool = False,
    recursion_depth: int = 0,
    file_size_probe: object = None,
    artifact_read_snapshot: object = None,
) -> TimeoutBudget:
    """Compute one permissive, deterministic hard-timeout budget."""
    components = build_timeout_budget_components(
        path,
        configured_timeout_seconds=configured_timeout_seconds,
        workload_class=workload_class,
        method=method,
        tags=tags,
        deep_scan=deep_scan,
        recursion_depth=recursion_depth,
        file_size_probe=file_size_probe,
        artifact_read_snapshot=artifact_read_snapshot,
    )
    return TimeoutBudget(
        workload_class=components.workload,
        method=components.method,
        hard_timeout_seconds=components.policy_output.hard_timeout_seconds,
        stall_timeout_seconds=components.policy_output.stall_timeout_seconds,
        heartbeat_stale_seconds=components.policy_output.heartbeat_stale_seconds,
        file_size=int(components.file_size),
        compressed_size=int(components.file_size),
        estimated_uncompressed_size=components.expanded_size,
        archive_member_count=components.archive_member_count,
        largest_member_size=components.largest_member_size,
        compression_ratio=components.compression_ratio,
        recursion_depth=components.recursion_depth,
        nested_archive_count=components.nested_archive_count,
        deep_scan=components.deep_scan,
        image_pixels=components.image_pixels,
        inspection_error=components.inspection_error,
    )


def annotate_timeout_result(result: Mapping[str, object] | dict[str, object], budget: TimeoutBudget, *, worker_state: str, reason: str, elapsed_seconds: float | None = None) -> dict[str, object]:
    annotated = dict(result) if type(result) is dict else {}
    evidence = budget.as_evidence()
    worker_state_text, worker_state_reason = scheduler_text(worker_state, replacement_text="unknown", unsupported_reason="worker_state_rejected")
    reason_text, reason_reason = scheduler_text(reason, replacement_text="timeout", unsupported_reason="timeout_reason_rejected")
    elapsed_value, elapsed_reason = scheduler_float(elapsed_seconds, default=0.0, minimum=0.0, reason="elapsed_seconds_rejected")
    evidence.update({
        "worker_state": worker_state_text if worker_state_reason == "" else "unknown",
        "timeout_reason": reason_text if reason_reason == "" else "timeout",
        "elapsed_seconds": round(elapsed_value, 6) if elapsed_seconds is not None and elapsed_reason == "" else None,
    })
    annotated["timeout_evidence"] = evidence
    integrity_source = scheduler_mapping_value(annotated, "scan_integrity")
    integrity = dict(integrity_source) if type(integrity_source) is dict else {}
    integrity.update({
        "file_failed": True,
        "had_degraded_stage": True,
        "allow_learning": False,
        "timeout_budget": evidence["timeout_budget"],
        "timeout_reason": evidence["timeout_reason"],
        "worker_state": evidence["worker_state"],
    })
    annotated["scan_integrity"] = integrity
    return annotated


__all__ = ("TimeoutBudget", "annotate_timeout_result", "compute_timeout_budget")
