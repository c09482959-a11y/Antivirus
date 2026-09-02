"""Public scheduler runtime/queue coordination API.

This module is the production-callable scheduler API surface for small
runtime/queue coordination contracts needed outside scheduler internals.  It
uses only direct canonical imports, no dynamic import, and no import-time orchestration.
"""
from __future__ import annotations

from Virus_Scan.scheduler.runtime.multiprocessing_context import (
    get_scheduler_multiprocessing_context,
    scheduler_worker_shared_persistence_writes_disabled,
)
from Virus_Scan.scheduler.queue.raw_retry_job import prepare_raw_retry_job
from Virus_Scan.scheduler.queue.identity_index import note_identity_for_queue
from Virus_Scan.scheduler.queue.admission import (
    build_workload_classification_plan,
    workload_plan_summary,
)
from Virus_Scan.scheduler.runtime.stage_budget import (
    acquire_weighted_stage_budget,
    estimate_stage_file_cost,
    record_stage_cost_observation,
    release_weighted_stage_budget,
    stage_limit_for_name,
    stage_semaphore_for_name,
    weighted_stage_tokens,
)

__all__ = (
    "acquire_weighted_stage_budget",
    "estimate_stage_file_cost",
    "get_scheduler_multiprocessing_context",
    "note_identity_for_queue",
    "prepare_raw_retry_job",
    "record_stage_cost_observation",
    "release_weighted_stage_budget",
    "scheduler_worker_shared_persistence_writes_disabled",
    "stage_limit_for_name",
    "stage_semaphore_for_name",
    "weighted_stage_tokens",
    "build_workload_classification_plan",
    "workload_plan_summary",
)
