"""Constructor-owned live state for the in-memory scheduler."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex
from Virus_Scan.scheduler.ownership.inmemory_live_state_materialization import (
    live_ewma_snapshot,
    live_mapping_snapshot,
    live_process_snapshot,
    live_set_snapshot,
)

if TYPE_CHECKING:
    from Virus_Scan.scheduler.ownership.inmemory_live_state_contract import LiveStateFieldOutcome, LiveStateRejection


@dataclass
class InMemoryLiveSchedulerState:
    active: dict[object, object] = field(default_factory=dict)
    worker_heartbeats: dict[object, object] = field(default_factory=dict)
    worker_metrics: dict[object, object] = field(default_factory=dict)
    done: set[object] = field(default_factory=set)
    failed: set[object] = field(default_factory=set)
    terminal: set[object] = field(default_factory=set)
    results: dict[object, object] = field(default_factory=dict)
    processes: list[object] = field(default_factory=list)
    ewma_state: dict[str, float] = field(default_factory=dict)
    state_index: InMemorySchedulerStateIndex = field(default_factory=InMemorySchedulerStateIndex)
    constructor_rejections: tuple[LiveStateRejection, ...] = field(default_factory=tuple)
    constructor_outcomes: tuple[LiveStateFieldOutcome, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        # This object is the context-owned mutable state holder for one
        # in-memory scheduler run.  It may mutate its own top-level containers,
        # but it must not retain caller-owned containers or execute caller-owned
        # conversion hooks during direct construction.
        active = live_mapping_snapshot(self.active, field_name="active")
        worker_heartbeats = live_mapping_snapshot(self.worker_heartbeats, field_name="worker_heartbeats")
        worker_metrics = live_mapping_snapshot(self.worker_metrics, field_name="worker_metrics")
        done = live_set_snapshot(self.done, field_name="done")
        failed = live_set_snapshot(self.failed, field_name="failed")
        terminal = live_set_snapshot(self.terminal, field_name="terminal")
        results = live_mapping_snapshot(self.results, field_name="results")
        processes = live_process_snapshot(self.processes, field_name="processes")
        ewma_state = live_ewma_snapshot(self.ewma_state)

        self.active = active.value
        self.worker_heartbeats = worker_heartbeats.value
        self.worker_metrics = worker_metrics.value
        self.done = done.value
        self.failed = failed.value
        self.terminal = terminal.value
        self.results = results.value
        self.processes = processes.value
        self.ewma_state = ewma_state.value
        self.constructor_rejections = (
            active.rejections
            + worker_heartbeats.rejections
            + worker_metrics.rejections
            + done.rejections
            + failed.rejections
            + terminal.rejections
            + results.rejections
            + processes.rejections
            + ewma_state.rejections
        )
        self.constructor_outcomes = (
            active.outcome,
            worker_heartbeats.outcome,
            worker_metrics.outcome,
            done.outcome,
            failed.outcome,
            terminal.outcome,
            results.outcome,
            processes.outcome,
            ewma_state.outcome,
        )


def build_inmemory_live_scheduler_state() -> InMemoryLiveSchedulerState:
    """Create context-owned scheduler live state for one in-memory run."""
    return InMemoryLiveSchedulerState()
