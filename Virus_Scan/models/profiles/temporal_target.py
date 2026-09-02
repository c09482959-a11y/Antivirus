"""Profiles-owned atomic target for trusted temporal baseline learning."""
from __future__ import annotations

from Virus_Scan.models.profiles.transaction_contracts import LearningCommitRequest
from Virus_Scan.models.temporal.dwell_baseline import apply_temporal_baseline_learning
from Virus_Scan.models.temporal.learning import build_temporal_learning_request
from Virus_Scan.runtime.temporal_state import (
    commit_temporal_learning_request,
    invalidate_temporal_cache,
)
from Virus_Scan.runtime import model_state as runtime_model_state


def apply_temporal_learning_target(
    profile: dict[str, object], request: LearningCommitRequest,
) -> dict[str, object]:
    """Prepare profile state, commit runtime once, then replace profile state."""
    request.validate()
    model_state = profile.get("model_state")
    if type(model_state) is not dict:
        return {"updated": False, "reason": "profile_model_state_unavailable"}
    store = model_state.get("temporal_baselines")
    try:
        temporal_request, validations = build_temporal_learning_request(
            learning_decision=request.decision,
            node=request.file_path,
            previous_stage=request.previous_stage,
            current_stage=request.current_stage,
            ordered_events=request.ordered_events,
            behavior_flow=request.behavior_flow,
        )
        prepared_store, baseline_result = apply_temporal_baseline_learning(
            store, temporal_request,
        )
        runtime_applied = commit_temporal_learning_request(temporal_request)
    except (TypeError, ValueError):
        return {"updated": False, "reason": "temporal_target_contract_invalid"}
    model_state["temporal_baselines"] = prepared_store
    if runtime_applied:
        invalidate_temporal_cache(request.file_path)
        runtime_model_state.mark_runtime_models_dirty()
    return {
        "updated": True,
        "reason": baseline_result["reason"],
        "transitions": baseline_result["transitions"],
        "idempotent_replay": (
            baseline_result["idempotent_replay"] and not runtime_applied
        ),
        "runtime_mutated": runtime_applied,
        "source_record_digest": temporal_request.source_record_digest,
        "event_validation_count": len(validations),
    }


__all__ = ("apply_temporal_learning_target",)
