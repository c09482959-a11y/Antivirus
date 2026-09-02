"""Process-queue child environment ownership.

This runtime module owns construction of the immutable environment snapshot used
when spawning process-queue children.  The execution runner supplies only the
runtime inputs; it does not mutate or assemble child process environment state.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scheduler.internal.immutable_output_support import frozen_scheduler_items_decision
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_text

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_text_mapping_from_items


@dataclass(frozen=True)
class ProcessQueueChildEnvironmentRequest:
    env: Mapping[str, str]
    dynamic_queue_feed: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "env", immutable_mapping(self.env))
        dynamic_queue_feed, _reason = scheduler_bool(
            self.dynamic_queue_feed,
            default=False,
            reason="process_queue_child_environment_dynamic_feed_rejected",
        )
        object.__setattr__(self, "dynamic_queue_feed", dynamic_queue_feed)


@dataclass(frozen=True)
class ProcessQueueChildEnvironmentDependencies:
    runtime_value: Callable[[str, object], object]


@dataclass(frozen=True)
class ProcessQueueChildEnvironmentOutput:
    env: Mapping[str, str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "env", immutable_mapping(self.env))


def build_process_queue_child_environment(
    request: ProcessQueueChildEnvironmentRequest,
    dependencies: ProcessQueueChildEnvironmentDependencies,
) -> ProcessQueueChildEnvironmentOutput:
    """Return an immutable child environment snapshot for process workers."""

    frozen_decision = frozen_scheduler_items_decision(request.env)
    env_items = frozen_decision.items if frozen_decision.accepted else None
    if env_items is None:
        env_items = no_hook_mapping_items(request.env)
    env_base = scheduler_str_text_mapping_from_items(env_items)
    env_base["UMIGE_PROCESS_SHARD"] = "1"
    env_base["UMIGE_PROCESS_QUEUE"] = "1"
    env_base["UMIGE_DYNAMIC_QUEUE_FEED"] = "1" if request.dynamic_queue_feed else "0"
    deep_scan_value, deep_scan_reason = scheduler_text(
        dependencies.runtime_value(
            "DEEP_SCAN_MODE",
            dict.get(env_base, "UMIGE_DEEP_SCAN_MODE", "auto"),
        ),
        unsupported_reason="process_queue_child_environment_deep_scan_rejected",
    )
    env_base["UMIGE_DEEP_SCAN_MODE"] = deep_scan_value if not deep_scan_reason and deep_scan_value else "auto"
    return ProcessQueueChildEnvironmentOutput(env=env_base)


__all__ = (
    "ProcessQueueChildEnvironmentDependencies",
    "ProcessQueueChildEnvironmentOutput",
    "ProcessQueueChildEnvironmentRequest",
    "build_process_queue_child_environment",
)
