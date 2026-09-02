"""In-memory result timeout/routing evidence enrichment ownership."""
from __future__ import annotations

from typing import Callable, Mapping

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_value
from Virus_Scan.scheduler.evidence.inmemory_route_identity import consume_inmemory_route_identity
from Virus_Scan.routing.context_identity import attached_routing_evidence_identity
from Virus_Scan.scheduler.evidence.inmemory_result_timeout_support import (
    first_mapping_value,
    timeout_bool,
    timeout_float,
    timeout_int,
    timeout_mapping,
    timeout_tags,
    timeout_text,
)



def attach_inmemory_result_evidence(*, result: object, record: Mapping[str, object], path: object, worker_pid: object, container_root: object, evidence_context: object, routing_evidence_attacher: Callable[..., object], wall_time: Callable[[], float]) -> object:
    """Attach scheduler timeout evidence before result publication."""
    if type(result) is not dict:
        return result
    enriched = dict.copy(result)
    router_identity = consume_inmemory_route_identity(enriched)
    rejections: list[dict[str, object]] = []
    now_done = wall_time()
    last_hb_raw = first_mapping_value(
        record,
        ("last_heartbeat", "running_at", "started_at"),
        now_done,
    )
    last_hb = timeout_float(
        last_hb_raw,
        default_value=now_done,
        field="last_heartbeat",
        rejections=rejections,
    )
    last_progress = timeout_float(
        first_mapping_value(record, ("last_progress_time",), last_hb),
        default_value=last_hb,
        field="last_progress_time",
        rejections=rejections,
    )
    source = first_mapping_value(enriched, ("timeout_evidence",), None)
    if source is None:
        source = first_mapping_value(record, ("timeout_budget",), None)
    existing = timeout_mapping(source, field="timeout_evidence", rejections=rejections)
    timeout_evidence = {
        **existing,
        "worker_state": timeout_text(
            scheduler_mapping_value(existing, "worker_state", "queue_worker_alive_progressing"),
            default_value="queue_worker_alive_progressing",
            field="worker_state",
            rejections=rejections,
        ),
        "heartbeat_age": scheduler_mapping_value(
            existing,
            "heartbeat_age",
            round(max(0.0, now_done - last_hb), 6),
        ),
        "progress_age": scheduler_mapping_value(
            existing,
            "progress_age",
            round(max(0.0, now_done - last_progress), 6),
        ),
        "current_stage": timeout_text(
            scheduler_mapping_value(existing, "current_stage", scheduler_mapping_value(record, "stage", "scan")),
            default_value="scan",
            field="current_stage",
            rejections=rejections,
        ),
        "progress_counter": timeout_int(
            scheduler_mapping_value(existing, "progress_counter", scheduler_mapping_value(record, "progress_counter", 0)),
            default_value=0,
            field="progress_counter",
            rejections=rejections,
        ),
        "bytes_processed": timeout_int(
            scheduler_mapping_value(existing, "bytes_processed", scheduler_mapping_value(record, "bytes_processed", 0)),
            default_value=0,
            field="bytes_processed",
            rejections=rejections,
        ),
        "worker_pid": timeout_int(
            scheduler_mapping_value(existing, "worker_pid", first_mapping_value(record, ("pid",), worker_pid)),
            default_value=0,
            field="worker_pid",
            rejections=rejections,
        ),
        "worker_recovered": timeout_bool(
            scheduler_mapping_value(existing, "worker_recovered", False),
            field="worker_recovered",
            rejections=rejections,
        ),
        "worker_killed": timeout_bool(
            scheduler_mapping_value(existing, "worker_killed", False),
            field="worker_killed",
            rejections=rejections,
        ),
    }
    if rejections:
        timeout_evidence["scheduler_timeout_input_rejections"] = tuple(rejections)
        timeout_evidence["scheduler_evidence_status"] = "degraded"
    enriched["timeout_evidence"] = timeout_evidence
    if "worker_state" not in enriched:
        enriched["worker_state"] = timeout_evidence.get("worker_state")
    if "timeout_budget" not in enriched:
        enriched["timeout_budget"] = timeout_evidence.get("timeout_budget")
    tags = timeout_tags(scheduler_mapping_value(enriched, "tags"), rejections=rejections)
    trusted_benign = timeout_bool(scheduler_mapping_value(enriched, "trusted_benign"), field="trusted_benign", rejections=rejections)
    degraded = any(timeout_bool(scheduler_mapping_value(enriched, field), field=field, rejections=rejections) for field in ("error", "errors", "crash_traceback", "timed_out", "queue_failure")) or bool(rejections)
    if rejections:
        timeout_evidence["scheduler_timeout_input_rejections"] = tuple(rejections)
        timeout_evidence["scheduler_evidence_status"] = "degraded"
    if attached_routing_evidence_identity(enriched) is not None:
        return enriched
    return routing_evidence_attacher(
        enriched,
        path,
        container_root=container_root,
        tags=tags,
        trusted_benign=trusted_benign,
        degraded=degraded,
        evidence_context=evidence_context,
        router_identity=router_identity,
    )


__all__ = ("attach_inmemory_result_evidence",)
