"""Scheduler pipeline finalization ownership.

This module owns parent-side scheduler finalization that must happen after a
pipeline run: parent learning replay, persistent-model flushing, profile-policy
restoration, profile snapshot clearing, and the final partial JSON publication.
The execution pipeline passes immutable inputs and explicit dependencies; it no
longer mutates runtime/model/reporting state directly in its finalization block.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text, no_hook_type_name
from Virus_Scan.scheduler.internal.immutable_output_support import frozen_scheduler_items_decision
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_item_value
from Virus_Scan.contracts.retained_scan_result import (
    retained_parent_replay_payload,
    retained_result_marker_present,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping


@dataclass(frozen=True)
class SchedulerLearningCandidateDecision:
    """Replayable decision for parent-learning replay eligibility."""

    has_candidate: bool
    reason: str
    inspected_records: int


@dataclass(frozen=True)
class SchedulerPipelineFinalizationRequest:
    """Immutable request for scheduler pipeline finalization."""

    results: Mapping[str, object]
    scheduler_mode: str
    strict: bool
    process_shard: bool
    freeze_existing_baselines: bool
    profile_policy_snapshot: object

    def __post_init__(self) -> None:
        object.__setattr__(self, "results", immutable_mapping(self.results))


@dataclass(frozen=True)
class SchedulerPipelineFinalizationDependencies:
    """Explicit dependencies for scheduler pipeline finalization side effects."""

    persist_parent_learning_from_results: Callable[[Mapping[str, object]], object]
    flush_all_persistent_models: Callable[..., object]
    restore_profile_policy: Callable[[object], object]
    clear_profile_scoring_snapshot: Callable[[], object]
    write_partial: Callable[..., object]
    log_error: Callable[[str], object]
    recoverable_exceptions: tuple[type[BaseException], ...]


def _scheduler_mapping_items(value: object) -> tuple[tuple[object, object], ...] | None:
    frozen_decision = frozen_scheduler_items_decision(value)
    if frozen_decision.accepted:
        return frozen_decision.items
    return no_hook_mapping_items(value)



def scheduler_results_learning_candidate_decision(
    results: Mapping[str, object],
) -> SchedulerLearningCandidateDecision:
    """Return replayable parent-learning replay eligibility evidence."""

    items = _scheduler_mapping_items(results)
    if items is None:
        return SchedulerLearningCandidateDecision(
            False,
            "scheduler_learning_results_unavailable",
            0,
        )
    inspected_records = 0
    for _key, record in items:
        if _scheduler_mapping_items(record) is None:
            continue
        inspected_records += 1
        if retained_result_marker_present(record):
            if retained_parent_replay_payload(record) is not None:
                return SchedulerLearningCandidateDecision(
                    True,
                    "scheduler_retained_learning_candidate_available",
                    inspected_records,
                )
            continue
        fast_path = scheduler_mapping_item_value(
            _scheduler_mapping_items(record),
            "fast_path",
            False,
        )
        learn_eligible = scheduler_mapping_item_value(
            _scheduler_mapping_items(record),
            "learn_eligible",
            True,
        )
        if fast_path is True:
            continue
        if learn_eligible is False:
            continue
        return SchedulerLearningCandidateDecision(
            True,
            "scheduler_learning_candidate_available",
            inspected_records,
        )
    return SchedulerLearningCandidateDecision(
        False,
        "scheduler_learning_candidate_not_found",
        inspected_records,
    )


def scheduler_results_have_learning_candidate(results: Mapping[str, object]) -> bool:
    """Return whether any scheduler result should be replayed into learning."""

    return scheduler_results_learning_candidate_decision(results).has_candidate


def _persistent_flush_failed(result: object) -> bool:
    items = no_hook_mapping_items(result, allow_dict_subclass=True)
    if items is None:
        return False
    for key, value in items:
        if key == "ok":
            return value is not True
    return False


def finalize_scheduler_pipeline(
    request: SchedulerPipelineFinalizationRequest,
    dependencies: SchedulerPipelineFinalizationDependencies,
) -> None:
    """Finalize a scheduler pipeline run through the canonical finalization owner."""

    results = request.results if request.results is not None else immutable_mapping()
    scheduler_mode_text, scheduler_mode_reason = no_hook_text(
        request.scheduler_mode,
        missing_reason="missing_scheduler_mode",
        unsupported_reason="scheduler_mode_text_rejected",
    )
    scheduler_mode = str.__str__(scheduler_mode_text).lower() if not scheduler_mode_reason and scheduler_mode_text else "process"
    try:
        if not request.process_shard:
            try:
                has_learning_candidate = scheduler_results_have_learning_candidate(results)
                if scheduler_mode in {"process", "process-fs", "filesystem-queue"} and has_learning_candidate:
                    dependencies.persist_parent_learning_from_results(results)
            except dependencies.recoverable_exceptions as exc:
                error_text, error_reason = no_hook_text(
                    exc,
                    missing_reason="missing_scheduler_exception_text",
                    unsupported_reason="scheduler_exception_text_rejected",
                )
                error_label = no_hook_type_name(exc) if error_reason else error_text
                dependencies.log_error("parent learning replay failed at pipeline end: " + error_label)
                if request.strict:
                    raise
            has_learning_candidate = scheduler_results_have_learning_candidate(results)
            if has_learning_candidate:
                flush_result = dependencies.flush_all_persistent_models(force=True)
                if _persistent_flush_failed(flush_result):
                    dependencies.log_error("persistent model flush failed at pipeline end: persistent_model_flush_failed")
                    if request.strict:
                        raise RuntimeError("persistent_model_flush_failed")
    except dependencies.recoverable_exceptions as exc:
        error_text, error_reason = no_hook_text(
            exc,
            missing_reason="missing_scheduler_exception_text",
            unsupported_reason="scheduler_exception_text_rejected",
        )
        error_label = no_hook_type_name(exc) if error_reason else error_text
        dependencies.log_error("persistent model flush failed at pipeline end: " + error_label)
        if request.strict:
            raise
    finally:
        dependencies.restore_profile_policy(request.profile_policy_snapshot)
        if request.freeze_existing_baselines:
            dependencies.clear_profile_scoring_snapshot()
        dependencies.write_partial(force=True)
