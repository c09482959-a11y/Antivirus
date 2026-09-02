"""Canonical cross-domain activation of runtime scanner dependency providers.

Both the parent runtime and spawned scheduler workers enter scanner services through
this single activation owner.  The runtime registry remains the mutable process-local
port owner; scanner implementations remain owned by their public contracts.
"""
from __future__ import annotations

from Virus_Scan.runtime.api import (
    get_lifecycle_state,
    register_engine_context_detector,
    register_intrastage_provider,
    register_raw_string_stage_provider,
    register_scan_strings_provider,
    register_string_event_provider,
)
from Virus_Scan.routing.engine_detect import detect_target_engine_context
from Virus_Scan.routing.extension_intrastage import run_raw_task_queue
from Virus_Scan.routing.intrastage_executor_session import (
    effective_intrastage_enabled,
    effective_stage_parallel_workers,
)
from Virus_Scan.scanners.api import public_contracts as scanner_public_contracts


def activate_runtime_scan_dependency_providers() -> None:
    """Install the canonical scanner service providers in the current process."""
    register_scan_strings_provider(scanner_public_contracts.scan_strings_provider)
    register_string_event_provider(scanner_public_contracts.iter_ordered_string_events)
    register_raw_string_stage_provider(scanner_public_contracts.raw_stage_scan_strings)
    register_engine_context_detector(detect_target_engine_context)
    register_intrastage_provider(
        intrastage_enabled=effective_intrastage_enabled,
        run_raw_task_queue=run_raw_task_queue,
        stage_parallel_workers=effective_stage_parallel_workers,
        append_intrastage_string_tasks=scanner_public_contracts.append_intrastage_string_tasks,
    )
    get_lifecycle_state().mark_dependency_providers_registered()


__all__ = ("activate_runtime_scan_dependency_providers",)
