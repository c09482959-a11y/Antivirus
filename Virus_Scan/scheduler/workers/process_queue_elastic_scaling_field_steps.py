"""No-hook field parsing helpers for process-queue elastic scaling."""
from __future__ import annotations

from typing import NamedTuple

from Virus_Scan.scheduler.workers.process_queue_elastic_no_hook import elastic_bool, elastic_int
from Virus_Scan.scheduler.workers.process_queue_spawn_evidence import (
    ProcessQueueWorkerSpawnFailureEvidence,
)


class ElasticWorkerCountFields(NamedTuple):
    """No-hook worker-count fields parsed from an elastic scale request."""

    live_workers: int
    next_worker_spawn_id: int
    process_count: int
    requested_process_count: int
    enabled: bool
    worker_spawn_failures: tuple[ProcessQueueWorkerSpawnFailureEvidence, ...]


class ElasticQueueCountFields(NamedTuple):
    """No-hook queue-count fields parsed from an elastic scale request."""

    ordered_queue_count: int
    queue_feed_cursor: int
    file_pending_count: int
    file_active_count: int
    raw_live: int


def elastic_scale_failure(
    action: str,
    category: str,
    source: str,
    detail: str,
    worker_id: int | None = None,
) -> ProcessQueueWorkerSpawnFailureEvidence:
    return ProcessQueueWorkerSpawnFailureEvidence(
        stage="process_queue.elastic_scaling",
        action=action,
        worker_id=worker_id,
        error_category=category,
        error_source=source,
        detail=detail,
        fatal=False,
    )



def parse_elastic_worker_count_fields(request: object) -> ElasticWorkerCountFields:
    live, live_issue = elastic_int(
        request.live_workers,
        replacement=0,
        reason="process_queue_elastic_live_workers_rejected",
    )
    next_worker_spawn_id, spawn_id_issue = elastic_int(
        request.next_worker_spawn_id,
        replacement=0,
        reason="process_queue_elastic_next_worker_id_rejected",
    )
    process_count, process_count_issue = elastic_int(
        request.process_count,
        replacement=0,
        reason="process_queue_elastic_process_count_rejected",
    )
    requested_process_count, _requested_issue = elastic_int(
        request.requested_process_count,
        replacement=process_count,
        reason="process_queue_elastic_requested_count_rejected",
    )
    enabled, enabled_issue = elastic_bool(
        request.enabled,
        default=False,
        reason="process_queue_elastic_enabled_rejected",
    )
    failures = tuple(
        elastic_scale_failure(
            action,
            issue,
            "ProcessQueueElasticScaleRequest",
            "elastic scaling request field rejected before caller-owned hooks",
        )
        for action, issue in (
            ("enabled", enabled_issue),
            ("live_workers", live_issue),
            ("next_worker_spawn_id", spawn_id_issue),
            ("process_count", process_count_issue),
        )
        if issue
    )
    return ElasticWorkerCountFields(live, next_worker_spawn_id, process_count, requested_process_count, enabled, failures)


def parse_elastic_queue_count_fields(request: object) -> ElasticQueueCountFields:
    ordered_queue_count, _ordered_issue = elastic_int(
        request.ordered_queue_count,
        replacement=0,
        reason="process_queue_elastic_ordered_queue_count_rejected",
    )
    queue_feed_cursor, _cursor_issue = elastic_int(
        request.queue_feed_cursor,
        replacement=0,
        reason="process_queue_elastic_queue_feed_cursor_rejected",
    )
    file_pending_count, _pending_issue = elastic_int(
        request.file_pending_count,
        replacement=0,
        reason="process_queue_elastic_file_pending_count_rejected",
    )
    file_active_count, _active_issue = elastic_int(
        request.file_active_count,
        replacement=0,
        reason="process_queue_elastic_file_active_count_rejected",
    )
    raw_live, _raw_issue = elastic_int(
        request.raw_live,
        replacement=0,
        reason="process_queue_elastic_raw_live_rejected",
    )
    return ElasticQueueCountFields(
        ordered_queue_count,
        queue_feed_cursor,
        file_pending_count,
        file_active_count,
        raw_live,
    )


__all__ = (
    "ElasticQueueCountFields",
    "ElasticWorkerCountFields",
    "elastic_scale_failure",
    "parse_elastic_queue_count_fields",
    "parse_elastic_worker_count_fields",
)
