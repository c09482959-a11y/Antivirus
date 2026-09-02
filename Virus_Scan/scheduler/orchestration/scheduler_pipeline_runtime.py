"""Runtime helpers for the canonical scheduler pipeline.

The public runner owns orchestration order. This module owns the bounded local
run state, partial-publication callback, and queue-child console setup. Per-file
worker construction is owned separately by ``scheduler_file_worker``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from Virus_Scan.scheduler.evidence.partial_checkpoint_cache import PartialCheckpointCache


@dataclass
class SchedulerPipelineRunState:
    """Explicit local mutable state for one scheduler pipeline invocation."""

    results: dict[object, object]
    last_partial_write: float = 0.0
    partial_checkpoint_cache: PartialCheckpointCache = field(
        default_factory=PartialCheckpointCache,
    )


def maybe_install_queue_child_console_handlers(
    *,
    scheduler_requested: str,
    runtime_environment_owner_factory: Callable[[], object],
    signal_module: object,
    install_handlers: Callable[..., object],
    record_suppressed: Callable[..., object],
) -> None:
    """Install child console handlers only for queue-child scheduler mode."""

    if scheduler_requested == "queue-child":
        install_handlers(
            environ=runtime_environment_owner_factory().snapshot(),
            signal_module=signal_module,
            record_suppressed=record_suppressed,
        )


def build_partial_result_writer(
    *,
    state: SchedulerPipelineRunState,
    dependencies: object,
    partial_output_path: object,
    total_files: int,
    partial_output_every: int,
) -> Callable[[bool], None]:
    """Build the scan-owned checkpoint callback with the public keyword contract."""

    def write_partial(force: bool = False) -> None:
        state.last_partial_write = dependencies.write_partial_scheduler_results(
            partial_output_path=partial_output_path,
            results=state.results,
            total_files=total_files,
            partial_output_every=partial_output_every,
            last_partial_write=state.last_partial_write,
            now=dependencies.time,
            environ_get=dependencies.environ_get,
            write_partial_scan_results=dependencies.write_partial_scan_results,
            make_json_safe=dependencies.make_json_safe,
            log_error=dependencies.log_error,
            checkpoint_cache=state.partial_checkpoint_cache,
            force=force,
        )

    return write_partial


__all__ = (
    "SchedulerPipelineRunState",
    "build_partial_result_writer",
    "maybe_install_queue_child_console_handlers",
)
