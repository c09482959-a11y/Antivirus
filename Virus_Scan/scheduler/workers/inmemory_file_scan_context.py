"""Context construction for in-memory file scan execution."""
from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Callable

from Virus_Scan.contracts.artifact_read_snapshot import (
    ArtifactReadSnapshot,
    build_artifact_read_snapshot,
)
from Virus_Scan.contracts.scan_session_snapshot import ScanSessionSnapshot
from Virus_Scan.routing.context_evidence_context import RoutingEvidenceContext
from Virus_Scan.scheduler.workers.heartbeat import UmigeCooperativeCancel
from Virus_Scan.scheduler.workers.inmemory_file_scan_support import (
    cfg_value,
    owned_cfg_snapshot,
    worker_bool,
    worker_float,
    worker_int,
    worker_non_empty_text,
)
from Virus_Scan.scheduler.workers.inmemory_scan_progress import InMemoryScanProgressEmitter
from Virus_Scan.scheduler.workers.result_contracts import make_scheduler_worker_error_result


@dataclass(slots=True)
class InMemoryScanContext:
    path: object
    cfg: dict[str, object]
    started_file: float
    prev_stage: str
    per_file_timeout_sec: int
    slow_file_warn_sec: float
    strict: bool
    yara_enabled: bool
    scan_session_snapshot: ScanSessionSnapshot
    routing_evidence_context: RoutingEvidenceContext
    artifact_read_snapshot: ArtifactReadSnapshot
    compiled_rules: object
    progress: InMemoryScanProgressEmitter
    timeout_budget_factory: Callable[..., object]
    timeout_result_annotator: Callable[..., object]
    timeout_error_type: type[BaseException]
    active_timeout_budget: object


@dataclass(frozen=True, slots=True)
class InMemoryScanSetup:
    context: InMemoryScanContext | None
    early_result: object | None


def build_inmemory_scan_context(
    *,
    path: object,
    cfg: object,
    timeout_budget_factory: object = None,
    timeout_result_annotator: object = None,
    timeout_error_type: object = None,
    recoverable_exceptions: tuple[type[BaseException], ...],
    record_suppressed: Callable[[str, BaseException], object],
) -> InMemoryScanSetup:
    cfg_snapshot = owned_cfg_snapshot(cfg)
    if cfg_snapshot is None:
        return InMemoryScanSetup(
            None,
            (path, make_scheduler_worker_error_result(path, RuntimeError("invalid in-memory worker config"))),
        )
    if timeout_budget_factory is None:
        timeout_budget_factory = cfg_value(cfg_snapshot, "timeout_budget_factory")
    if timeout_result_annotator is None:
        timeout_result_annotator = cfg_value(cfg_snapshot, "timeout_result_annotator")
    if timeout_error_type is None:
        timeout_error_type = cfg_value(cfg_snapshot, "timeout_error_type")
    if timeout_budget_factory is None or timeout_result_annotator is None or timeout_error_type is None:
        return InMemoryScanSetup(
            None,
            (path, make_scheduler_worker_error_result(path, RuntimeError("missing in-memory timeout ownership dependencies"))),
        )
    per_file_timeout_sec = worker_int(
        cfg_value(cfg_snapshot, "per_file_timeout_sec"),
        reason="inmemory_per_file_timeout_rejected",
    )
    artifact_read_snapshot = build_artifact_read_snapshot(path)
    active_timeout_budget = timeout_budget_factory(
        path,
        configured_timeout_seconds=per_file_timeout_sec,
        method="routing_triage",
        artifact_read_snapshot=artifact_read_snapshot,
    )
    progress = InMemoryScanProgressEmitter(
        progress_callback=cfg_value(cfg_snapshot, "progress_callback"),
        cancel_error_type=UmigeCooperativeCancel,
        recoverable_exceptions=recoverable_exceptions,
        record_suppressed=record_suppressed,
    )
    scan_session_snapshot = cfg_value(cfg_snapshot, "scan_session_snapshot")
    routing_evidence_context = cfg_value(cfg_snapshot, "routing_evidence_context")
    compiled_rules = cfg_value(cfg_snapshot, "compiled_rules")
    if type(scan_session_snapshot) is not ScanSessionSnapshot:
        return InMemoryScanSetup(
            None,
            (path, make_scheduler_worker_error_result(path, RuntimeError("missing scan session snapshot"))),
        )
    if type(routing_evidence_context) is not RoutingEvidenceContext:
        return InMemoryScanSetup(
            None,
            (path, make_scheduler_worker_error_result(path, RuntimeError("missing routing evidence context"))),
        )
    return InMemoryScanSetup(
        InMemoryScanContext(
            path=path,
            cfg=cfg_snapshot,
            started_file=time.time(),
            prev_stage=worker_non_empty_text(cfg_value(cfg_snapshot, "prev_stage")) or "unknown",
            per_file_timeout_sec=per_file_timeout_sec,
            slow_file_warn_sec=worker_float(
                cfg_value(cfg_snapshot, "slow_file_warn_sec"),
                reason="inmemory_slow_file_warn_rejected",
            ),
            strict=worker_bool(cfg_value(cfg_snapshot, "strict")),
            yara_enabled=worker_bool(cfg_value(cfg_snapshot, "yara_enabled"), default=True),
            scan_session_snapshot=scan_session_snapshot,
            routing_evidence_context=routing_evidence_context,
            artifact_read_snapshot=artifact_read_snapshot,
            compiled_rules=compiled_rules,
            progress=progress,
            timeout_budget_factory=timeout_budget_factory,
            timeout_result_annotator=timeout_result_annotator,
            timeout_error_type=timeout_error_type,
            active_timeout_budget=active_timeout_budget,
        ),
        None,
    )


__all__ = (
    "InMemoryScanContext",
    "InMemoryScanSetup",
    "build_inmemory_scan_context",
)
