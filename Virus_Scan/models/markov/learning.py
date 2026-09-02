from __future__ import annotations

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.runtime import model_state as runtime_model_state
from Virus_Scan.runtime.model_state import commit_markov_update_request
from Virus_Scan.contracts.markov_learning import (
    MARKOV_DISPOSITION_TRUSTED_BENIGN,
    MARKOV_MODEL_VERSION,
    MARKOV_STATE_SCHEMA_VERSION,
    MarkovUpdateRequest,
)
from Virus_Scan.models.contracts.model_evidence import make_model_evidence_record
from Virus_Scan.models.contracts.learning_authority import (
    LearningDecision,
    learning_authorization_failure,
)
from Virus_Scan.models.markov.flow import canonical_behavior_flow, safe_markov_stage_name


def _learning_record(values: dict[str, object]) -> object:
    return make_model_evidence_record(
        values,
        model_name="markov",
        evidence_type="learning_update",
        model_version="markov_learning_update_v2",
    )


def _markov_update_request(
    decision: object,
    *,
    previous_stage: str,
    current_stage: str,
    behavior_flow: tuple[str, ...],
) -> MarkovUpdateRequest:
    """Convert one validated profile decision into the runtime data contract."""
    if type(decision) is not LearningDecision:
        raise ValueError("markov learning decision required")
    decision.validate()
    if not decision.authorizes("markov"):
        raise ValueError("markov learning decision unauthorized")
    request = MarkovUpdateRequest(
        observation_id=decision.observation_id,
        observation_digest=decision.observation_digest,
        source_record_digest=decision.observation_digest,
        previous_stage=previous_stage,
        current_stage=current_stage,
        behavior_flow=behavior_flow,
        engine=decision.engine,
        context_identity=decision.context_identity,
        learning_disposition=MARKOV_DISPOSITION_TRUSTED_BENIGN,
        disposition_provenance=(
            decision.schema_version
            + ":"
            + decision.gate_version
            + ":"
            + decision.reason
        ),
        gate_version=decision.gate_version,
        decision_ordinal=decision.decision_ordinal,
        replay_key=decision.replay_key,
    )
    request.validate()
    return request


def update_markov_model(
    prev_stage: object,
    tags: object,
    curr_stage: object,
    *,
    learning_decision: object = None,
) -> object:
    """Apply one profiles-authorized contextual Markov observation atomically."""
    authorization_reason = learning_authorization_failure(learning_decision, "markov")
    if authorization_reason is not None:
        return _learning_record(
            {
                "learned": False,
                "reason": authorization_reason,
                "flow": (),
                "transitions": 0,
                "state_schema": MARKOV_STATE_SCHEMA_VERSION,
            }
        )
    flow = canonical_behavior_flow(tags)
    if len(flow) < 2:
        return _learning_record(
            {
                "learned": False,
                "reason": "insufficient_behavior_flow",
                "flow": flow,
                "transitions": 0,
                "state_schema": MARKOV_STATE_SCHEMA_VERSION,
            }
        )
    previous_stage = safe_markov_stage_name(prev_stage)
    current_stage = safe_markov_stage_name(curr_stage)
    if previous_stage == "unknown" or current_stage == "unknown":
        return _learning_record(
            {
                "learned": False,
                "reason": "markov_stage_unavailable",
                "flow": flow,
                "transitions": 0,
                "previous_stage": previous_stage,
                "current_stage": current_stage,
                "state_schema": MARKOV_STATE_SCHEMA_VERSION,
            }
        )
    try:
        request = _markov_update_request(
            learning_decision,
            previous_stage=previous_stage,
            current_stage=current_stage,
            behavior_flow=flow,
        )
        applied = commit_markov_update_request(request)
        if applied:
            runtime_model_state.mark_runtime_models_dirty()
    except (ValueError, TypeError):
        return _learning_record(
            {
                "learned": False,
                "reason": "markov_update_request_invalid",
                "flow": flow,
                "transitions": 0,
                "previous_stage": previous_stage,
                "current_stage": current_stage,
                "state_schema": MARKOV_STATE_SCHEMA_VERSION,
            }
        )
    except RECOVERABLE_RUNTIME_ERRORS:
        log_error("markov update failed")
        return _learning_record(
            {
                "learned": False,
                "reason": "runtime_model_state_error",
                "flow": flow,
                "transitions": 0,
                "previous_stage": previous_stage,
                "current_stage": current_stage,
                "state_schema": MARKOV_STATE_SCHEMA_VERSION,
            }
        )
    return _learning_record(
        {
            "learned": True,
            "reason": None,
            "flow": flow,
            "transitions": len(flow) - 1,
            "previous_stage": previous_stage,
            "current_stage": current_stage,
            "learning_disposition": request.learning_disposition,
            "context_levels": tuple(level for level, _key in request.context_levels()),
            "source_record_digest": request.source_record_digest,
            "state_schema": MARKOV_STATE_SCHEMA_VERSION,
            "idempotent_replay": not applied,
        }
    )


__all__ = ("update_markov_model",)
