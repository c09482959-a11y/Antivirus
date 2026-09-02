"""Public scheduler API entry.

This module owns only the public scheduler entry point. Real execution is owned
by scheduler.orchestration.scheduler_runner so api does not mix public API and
queue/worker/timeout/reconciliation behavior.
"""
from __future__ import annotations

from Virus_Scan.orchestration.bootstrap_initialization import initialize_runtime
from Virus_Scan.contracts.retained_scan_result import (
    retained_publication_record,
    retained_result_marker_present,
)
from Virus_Scan.runtime.api import init_state_snapshot
from Virus_Scan.scheduler.internal.scheduler_config import init_raw_scheduler_defaults
from Virus_Scan.scheduler.orchestration.scheduler_runner import run_scheduler_pipeline
from Virus_Scan.scheduler.runtime.resource_priority import init_scheduler_resources
from Virus_Scan.scheduler.runtime.startup_defaults import init_scheduler_defaults

PUBLIC_RESULT_VIEW = "public_records"
RETAINED_PUBLICATION_RESULT_VIEW = "retained_publication_records"
_RESULT_VIEWS = frozenset({PUBLIC_RESULT_VIEW, RETAINED_PUBLICATION_RESULT_VIEW})


def _public_scheduler_results(value: object) -> object:
    """Project internal retained records to the established public result mapping."""
    if type(value) is not dict:
        return value
    public: dict[object, object] = {}
    for path, record in dict.items(value):
        public[path] = (
            retained_publication_record(record)
            if retained_result_marker_present(record)
            else record
        )
    return public


def run_pipeline_safe(
    *args: object,
    result_view: object = PUBLIC_RESULT_VIEW,
    **kwargs: object,
) -> object:
    """Run one canonical scheduler execution and project its requested result view."""
    if type(result_view) is not str or result_view not in _RESULT_VIEWS:
        raise ValueError("scheduler_result_view_invalid")
    # Direct API callers enter the same canonical bootstrap owner as CLI execution.
    initialize_runtime()
    retained = run_scheduler_pipeline(*args, **kwargs)
    if result_view == RETAINED_PUBLICATION_RESULT_VIEW:
        return retained
    return _public_scheduler_results(retained)


def initialize_scheduler() -> object:
    """Run scheduler initialization through the canonical public scheduler API."""
    init_scheduler_resources()
    init_scheduler_defaults()
    init_raw_scheduler_defaults()
    return init_state_snapshot()


__all__ = (
    "PUBLIC_RESULT_VIEW",
    "RETAINED_PUBLICATION_RESULT_VIEW",
    "initialize_scheduler",
    "run_pipeline_safe",
)
