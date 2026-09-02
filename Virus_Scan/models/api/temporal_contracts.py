"""Public temporal model contract boundary.

Detection/correlation/scoring callers must not import temporal implementation
modules directly.  The temporal model remains the canonical owner of temporal
validation and snapshot evidence; this module publishes the narrow public entry
points used outside the model layer.
"""
from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name
from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence, normalize_tag_evidence
from Virus_Scan.models.api.text_boundary import (
    public_api_contract_text,
    public_duplicate_mapping_key_label,
    public_first_unavailable_reason,
    public_unreadable_mapping_key_label,
    public_unreadable_value_label,
)
from Virus_Scan.models.contracts.learning_authority import learning_authorization_failure

from Virus_Scan.models.temporal.api import (
    compute_temporal_validation as owner_compute_temporal_validation,
    explain_temporal_drift as owner_explain_temporal_drift,
    snapshot_temporal as owner_snapshot_temporal,
    transition_probability_overlay as owner_transition_probability_overlay,
    update_temporal as owner_update_temporal,
)

_TEMPORAL_PUBLIC_INPUT_ERRORS = RECOVERABLE_RUNTIME_ERRORS + (ArithmeticError,)


def _detached_temporal_contract_text(value: object) -> str:
    """Return exact built-in temporal public text without str-subclass hooks."""
    text, _reason = public_api_contract_text(value, default_text="")
    return text


def _safe_public_temporal_text(value: object, *, default_text: str) -> tuple[str, str | None]:
    text, reason = public_api_contract_text(value, default_text=default_text)
    if reason is not None:
        return default_text, "unreadable_temporal_public_text"
    if text == "":
        return default_text, None
    return text, None


def _materialize_temporal_value(value: object) -> object:
    """Detach public temporal evidence into deterministic built-in containers."""
    items = no_hook_mapping_items(value)
    if items is not None:
        out: dict[str, object] = {}
        keyed: list[tuple[str, int, object]] = []
        for index, (key, child) in enumerate(items):
            key_text, key_reason = _safe_public_temporal_text(key, default_text=public_unreadable_mapping_key_label(index))
            if key_reason is not None:
                key_text = public_unreadable_mapping_key_label(index)
            keyed.append((key_text, index, child))
        for raw_key_text, index, child in sorted(keyed, key=lambda row: (row[0], row[1])):
            key_text = raw_key_text
            if key_text in out:
                key_text = public_duplicate_mapping_key_label(key_text, index)
            out[key_text] = _materialize_temporal_value(child)
        return out
    if isinstance(value, Mapping):
        return {
            "ready": False,
            "degraded": True,
            "unavailable_reason": "unsupported_public_mapping",
            "evidence_type": "temporal_public_contract_value_unavailable",
            "final_json_must_record": True,
            "replay_record_required": True,
        }
    if type(value) is list:
        return [_materialize_temporal_value(item) for item in value]
    if type(value) is tuple:
        return tuple(_materialize_temporal_value(item) for item in value)
    if type(value) in (set, frozenset):
        try:
            ordered = sorted(value, key=lambda item: (_safe_public_temporal_text(no_hook_type_name(item), default_text="")[0], _safe_public_temporal_text(item, default_text="<unreadable_public_set_item>")[0]))
        except _TEMPORAL_PUBLIC_INPUT_ERRORS:
            return ("<unreadable_public_set>",)
        return tuple(_materialize_temporal_value(item) for item in ordered)
    if type(value) is str:
        return str.__str__(_safe_public_temporal_text(value, default_text="")[0])
    if type(value) in (int, float, bool) or value is None:
        return value
    text, reason = _safe_public_temporal_text(value, default_text=public_unreadable_value_label(value))
    if reason is not None:
        return {
            "ready": False,
            "degraded": True,
            "unavailable_reason": reason,
            "evidence_type": "temporal_public_contract_value_unavailable",
            "value_type": no_hook_type_name(value),
            "final_json_must_record": True,
            "replay_record_required": True,
        }
    return text


def _materialize_temporal_baseline_input(value: object) -> object:
    """Detach one profile-owned v5 baseline store without caller hooks."""
    items = no_hook_mapping_items(value)
    if items is not None:
        out: dict[str, object] = {}
        for key, child in items:
            if type(key) is not str or key == "" or key in out:
                return _INVALID_TEMPORAL_BASELINE_INPUT
            materialized = _materialize_temporal_baseline_input(child)
            if materialized is _INVALID_TEMPORAL_BASELINE_INPUT:
                return _INVALID_TEMPORAL_BASELINE_INPUT
            out[key] = materialized
        return out
    if type(value) in (list, tuple):
        out_list: list[object] = []
        for child in value:
            materialized = _materialize_temporal_baseline_input(child)
            if materialized is _INVALID_TEMPORAL_BASELINE_INPUT:
                return _INVALID_TEMPORAL_BASELINE_INPUT
            out_list.append(materialized)
        return out_list
    if type(value) in (str, int, float, bool) or value is None:
        return value
    return _INVALID_TEMPORAL_BASELINE_INPUT


_INVALID_TEMPORAL_BASELINE_INPUT = object()


def _public_temporal_sequence(value: object) -> tuple[tuple[object, ...], str | None]:
    """Normalize public temporal sequences without caller-owned iteration hooks."""
    if value is None:
        return (), None
    if type(value) in (str, bytes, bytearray, bool, int, float):
        return (_materialize_temporal_value(value),), None
    if no_hook_mapping_items(value) is not None:
        return (_materialize_temporal_value(value),), None
    if isinstance(value, Mapping):
        return (), "unsupported_temporal_public_mapping_sequence"
    if type(value) in (tuple, list, set, frozenset):
        return tuple(_materialize_temporal_value(item) for item in value), None
    return (), "non_iterable_temporal_public_sequence"


def _temporal_contract_failure(reason: str, *, evidence_type: str) -> dict[str, object]:
    return {
        "score": 0.0,
        "hits": (str.__str__(evidence_type) + "_unavailable",),
        "ready": False,
        "degraded": True,
        "unavailable_reason": reason,
        "evidence_type": evidence_type,
        "final_json_must_record": True,
        "replay_record_required": True,
    }


def _temporal_overlay_contract_failure(reason: str) -> dict[str, object]:
    return {
        "schema_version": "5.0",
        "version": "temporal_probability_overlay_contract_failure_v5",
        "evidence_type": "sequence_probability",
        "ready": False,
        "probability_ready": False,
        "stage_probability_ready": False,
        "stage_probability": None,
        "sequence_probability": None,
        "pair_probabilities": (),
        "degraded": True,
        "unavailable_reason": reason,
        "cold_start_reason": reason,
        "temporal_model_version": "temporal_probability_overlay_contract_failure_v5",
        "final_json_must_record": True,
        "replay_record_required": True,
    }


def _temporal_snapshot_contract_failure(reason: str) -> dict[str, object]:
    return {
        "belief": 0.0,
        "ready": False,
        "degraded": True,
        "unavailable_reason": reason,
        "evidence_type": "temporal_snapshot",
        "final_json_must_record": True,
        "replay_record_required": True,
    }


def _temporal_update_contract_failure(reason: str) -> dict[str, object]:
    return {
        "updated": False,
        "ready": False,
        "degraded": True,
        "reason": reason,
        "unavailable_reason": reason,
        "evidence_type": "temporal_learning_update",
        "final_json_must_record": True,
        "replay_record_required": True,
    }


def _stage_text(value: object) -> tuple[str, str | None]:
    return _safe_public_temporal_text("unknown" if value is None else value, default_text="unknown")


def _node_text(value: object) -> tuple[str, str | None]:
    return _safe_public_temporal_text("<unknown>" if value is None else value, default_text="<unknown>")


def compute_temporal_validation(
    node: object,
    *,
    tags: object = None,
    prev_stage: object = None,
    curr_stage: object = None,
    markov: object = None,
    ordered_events: object = (),
    engine: object = "other",
    temporal_baselines: object = None,
) -> Mapping[str, object]:
    """Return temporal validation evidence from the canonical temporal model."""
    if type(tags) is TagEvidence:
        tag_evidence = tags
        tag_reason = None
    else:
        tag_values, tag_reason = _public_temporal_sequence(tags)
        tag_evidence = normalize_tag_evidence(tag_values) if tag_reason is None else TagEvidence()
    event_values, event_reason = _public_temporal_sequence(ordered_events)
    engine_text, engine_reason = _safe_public_temporal_text(engine, default_text="other")
    prev_stage_text, prev_stage_reason = _stage_text(prev_stage)
    curr_stage_text, curr_stage_reason = _stage_text(curr_stage)
    if tag_reason:
        return _temporal_contract_failure(tag_reason, evidence_type="temporal_validation")
    malformed_reason = public_first_unavailable_reason(
        event_reason, engine_reason, prev_stage_reason, curr_stage_reason,
    )
    if malformed_reason:
        return _temporal_contract_failure("temporal_validation_public_call_failed", evidence_type="temporal_validation")
    baseline_input = (
        None if temporal_baselines is None
        else _materialize_temporal_baseline_input(temporal_baselines)
    )
    if baseline_input is _INVALID_TEMPORAL_BASELINE_INPUT:
        baseline_input = None
    try:
        result = owner_compute_temporal_validation(
            node,
            tags=tag_evidence,
            prev_stage=prev_stage_text,
            curr_stage=curr_stage_text,
            markov=markov,
            ordered_events=event_values,
            engine=engine_text,
            temporal_baselines=baseline_input,
        )
    except _TEMPORAL_PUBLIC_INPUT_ERRORS:
        return _temporal_contract_failure("temporal_validation_public_call_failed", evidence_type="temporal_validation")
    if isinstance(result, Mapping):
        return _materialize_temporal_value(result)
    return _temporal_contract_failure("invalid_temporal_validation_output", evidence_type="temporal_validation")


def transition_probability_overlay(
    *,
    prev_stage: object = "unknown",
    tags: object = None,
    curr_stage: object = "unknown",
    ordered_events: object = (),
) -> Mapping[str, object]:
    """Return replay-safe overlay from canonical event provenance."""
    tag_values, tag_reason = _public_temporal_sequence(tags)
    event_values, event_reason = _public_temporal_sequence(ordered_events)
    prev_stage_text, prev_stage_reason = _stage_text(prev_stage)
    curr_stage_text, curr_stage_reason = _stage_text(curr_stage)
    malformed_reason = public_first_unavailable_reason(
        tag_reason, event_reason, prev_stage_reason, curr_stage_reason,
    )
    if malformed_reason:
        return _temporal_overlay_contract_failure(malformed_reason)
    try:
        result = owner_transition_probability_overlay(
            prev_stage=prev_stage_text,
            tags=tag_values,
            curr_stage=curr_stage_text,
            ordered_events=event_values,
        )
    except _TEMPORAL_PUBLIC_INPUT_ERRORS:
        result = None
    if isinstance(result, Mapping):
        return _materialize_temporal_value(result)
    return _temporal_overlay_contract_failure(
        "invalid_temporal_probability_overlay_output"
    )


def snapshot_temporal(node: object) -> Mapping[str, object]:
    """Return temporal snapshot evidence from the canonical temporal model."""
    node_text, node_reason = _node_text(node)
    if node_reason is not None:
        return _temporal_snapshot_contract_failure("temporal_snapshot_public_input_invalid")
    try:
        result = owner_snapshot_temporal(node_text)
    except _TEMPORAL_PUBLIC_INPUT_ERRORS:
        return _temporal_snapshot_contract_failure("temporal_snapshot_public_input_invalid")
    if isinstance(result, Mapping):
        return _materialize_temporal_value(result)
    return _temporal_snapshot_contract_failure("invalid_temporal_snapshot_output")


def explain_temporal_drift(node: object) -> tuple[object, ...]:
    """Return temporal drift or explicit insufficient/unavailable evidence."""
    node_text, node_reason = _node_text(node)
    if node_reason is not None:
        return (_temporal_contract_failure(
            "temporal_drift_public_input_invalid",
            evidence_type="temporal_drift",
        ),)
    try:
        result = owner_explain_temporal_drift(node_text)
        snapshot = owner_snapshot_temporal(node_text)
    except _TEMPORAL_PUBLIC_INPUT_ERRORS:
        return (_temporal_contract_failure(
            "temporal_drift_public_call_failed",
            evidence_type="temporal_drift",
        ),)
    if type(result) not in (list, tuple):
        return (_temporal_contract_failure(
            "invalid_temporal_drift_output",
            evidence_type="temporal_drift",
        ),)
    if not result and isinstance(snapshot, Mapping) and snapshot.get("ready") is not True:
        reason = snapshot.get("unavailable_reason") or snapshot.get("reason")
        if type(reason) is not str or reason == "":
            reason = "temporal_drift_unavailable"
        return (_temporal_contract_failure(reason, evidence_type="temporal_drift"),)
    return tuple(_materialize_temporal_value(item) for item in result)


def update_temporal(
    node: object,
    stage: object,
    tags: object,
    *,
    previous_stage: object = "unknown",
    ordered_events: object = (),
    learning_decision: object = None,
) -> Mapping[str, object]:
    """Record one canonical profiles-authorized temporal request."""
    authorization_reason = learning_authorization_failure(
        learning_decision, "temporal",
    )
    if authorization_reason is not None:
        return _temporal_update_contract_failure(authorization_reason)
    if type(tags) is TagEvidence:
        tag_evidence = tags
        tag_reason = None
    else:
        tag_values, tag_reason = _public_temporal_sequence(tags)
        tag_evidence = (
            normalize_tag_evidence(tag_values) if tag_reason is None else TagEvidence()
        )
    event_values, event_reason = _public_temporal_sequence(ordered_events)
    node_text, node_reason = _node_text(node)
    stage_text, stage_reason = _stage_text(stage)
    previous_text, previous_reason = _stage_text(previous_stage)
    if tag_reason:
        return _temporal_update_contract_failure(tag_reason)
    malformed_reason = public_first_unavailable_reason(
        event_reason, node_reason, stage_reason, previous_reason,
    )
    if malformed_reason:
        return _temporal_update_contract_failure("invalid_temporal_update_output")
    try:
        result = owner_update_temporal(
            node_text,
            stage_text,
            tag_evidence,
            previous_stage=previous_text,
            ordered_events=event_values,
            learning_decision=learning_decision,
        )
    except _TEMPORAL_PUBLIC_INPUT_ERRORS:
        result = None
    if isinstance(result, Mapping):
        return _materialize_temporal_value(result)
    return _temporal_update_contract_failure("invalid_temporal_update_output")


__all__ = (
    "compute_temporal_validation",
    "explain_temporal_drift",
    "snapshot_temporal",
    "transition_probability_overlay",
    "update_temporal",
)
