"""Single profiles-owned online learning commit authority."""
from pathlib import Path
from Virus_Scan.models.api.learning_context_contracts import learning_guard
from Virus_Scan.models.profiles.adaptive_signal import infer_profile_engine
from Virus_Scan.models.profiles.baseline import get_extension_baseline
from Virus_Scan.models.profiles.common import (
    profile_finite_float, profile_has_mapping, profile_mapping_get,
    profile_mapping_items, profile_safe_text,
)
from Virus_Scan.models.profiles.commit_inputs import normalized_commit_inputs
from Virus_Scan.models.profiles.learning import (
    canonical_behavior_flow_from_sources, profile_learning_commit_unavailable,
)
from Virus_Scan.models.profiles.learning_decision import (
    build_learning_decision,
    content_sha256_for_path,
)
from Virus_Scan.models.profiles.learning_gate import (
    QUALITY_GATE_VERSION, record_learning_rejection,
    should_learn_scan_result,
)
from Virus_Scan.models.profiles.learning_transaction import execute_learning_transaction
from Virus_Scan.models.profiles.persistence import DEFAULT_ENGINES
from Virus_Scan.models.profiles.promotion import prepare_benign_observation
from Virus_Scan.models.profiles.request_contracts import ProfileLearningGateRequest
from Virus_Scan.models.profiles.transaction_contracts import LearningCommitRequest
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.models.profiles.staged_transaction import commit_staged_observation
from Virus_Scan.utils.stages import normalize_profile_extension, normalize_stage
def commit_promoted_learning(
    engine: object, file_path: object, tags: object, yara_hits: object = None,
    risk: object = 0.0, strings_blob: object = "", verdict: object = None,
    api_calls: object = None, ordered_events: object = None,
    behavior_flow: object = None, prev_stage: object = "unknown",
    curr_stage: object = "unknown", observation_id: object = None,
    scan_integrity: object = None,
) -> object:
    engine_text = engine if engine in DEFAULT_ENGINES else "other"
    values = normalized_commit_inputs(
        tags, yara_hits, api_calls, ordered_events, behavior_flow,
    )
    raw_tags, tags, yara_hits, api_calls, ordered_events, behavior_flow, malformed = values
    if malformed != "":
        return profile_learning_commit_unavailable(malformed)
    strings_text = profile_safe_text(strings_blob, replacement="")
    verdict_text = profile_safe_text(verdict, replacement="").lower()
    previous_stage = profile_safe_text(prev_stage, replacement="unknown") or "unknown"
    current_stage = profile_safe_text(curr_stage, replacement="unknown") or "unknown"
    risk_value = profile_finite_float(risk, 0.0)
    flow = tuple(canonical_behavior_flow_from_sources(
        raw_tags=raw_tags, ordered_events=ordered_events,
        behavior_flow=behavior_flow,
    ))
    integrity = dict(scan_integrity) if type(scan_integrity) is dict else {}
    with learning_guard() as entered:
        if not entered:
            return {"learned": False, "reason": "learning_reentry_blocked"}
        gate_request = ProfileLearningGateRequest(
            engine_text, file_path, tags, risk_value, strings_text, verdict_text,
            api_calls, ordered_events, scan_integrity=integrity,
        )
        allowed, reason, validation = should_learn_scan_result(gate_request)
        decision = build_learning_decision(
            gate_request, observation_id=observation_id, yara_hits=yara_hits,
            behavior_flow=flow, previous_stage=previous_stage,
            current_stage=current_stage, learning_allowed=allowed,
            reason=reason, validation=validation, gate_version=QUALITY_GATE_VERSION,
        )
        decision_record = decision.to_record()
        if not decision.authorizes("profile"):
            rejection_reason = decision.reason
            record_learning_rejection(engine_text, file_path, rejection_reason, validation)
            return {"learned": False, "reason": rejection_reason, "promoted": False,
                    "validation": validation, "learning_decision": decision_record}
        request = LearningCommitRequest(
            decision=decision, engine=engine_text,
            content_sha256=content_sha256_for_path(file_path), file_path=profile_safe_text(file_path, replacement=""),
            tag_evidence=tags, yara_hits=tuple(yara_hits), risk=risk_value,
            strings_blob=strings_text, verdict=verdict_text,
            api_calls=tuple(api_calls), ordered_events=tuple(ordered_events),
            behavior_flow=flow, previous_stage=previous_stage,
            current_stage=current_stage, validation=dict(validation),
            scan_integrity=integrity,
        )
        try:
            request.validate()
        except ValueError:
            return {"learned": False, "reason": "learning_commit_request_invalid",
                    "promoted": False, "validation": validation, "learning_decision": decision_record}
        transition = prepare_benign_observation(request)
        if not transition.promoted:
            try:
                transaction_id = commit_staged_observation(
                    transition.staged_store, replay_key=decision.replay_key,
                )
            except RECOVERABLE_RUNTIME_ERRORS as exc:
                return {
                    "learned": False, "promoted": False,
                    "reason": "learning_observation_ledger_persist_failed",
                    "error_type": type(exc).__name__, "validation": validation,
                    "learning_decision": decision_record,
                }
            return {
                "learned": False, "reason": transition.reason,
                "promoted": False, "candidate": transition.candidate,
                "transaction_id": transaction_id,
                "validation": validation, "learning_decision": decision_record,
            }
        result = execute_learning_transaction(request, transition.staged_store)
        result["validation"] = validation
        result["learning_decision"] = decision_record
        result["source_record_digest"] = decision.observation_digest
        return result
def update_profile_from_scan_result(
    file_path: object, tags: object, yara_hits: object = None,
    risk: object = 0.0, file_structure: object = None,
    strings_blob: object = "", verdict: object = None,
    api_calls: object = None, ordered_events: object = None,
) -> object:
    structure = file_structure if file_structure is not None else file_path
    strings_text = profile_safe_text(strings_blob, replacement="")
    engine, engine_ctx = infer_profile_engine(
        tags=tags, file_structure=structure,
        strings_blob=strings_text,
    )
    stage = normalize_stage(Path(profile_safe_text(file_path, replacement="")).suffix)
    result = commit_promoted_learning(
        engine, file_path, tags, yara_hits, risk, strings_text, verdict,
        api_calls, ordered_events, ordered_events, "unknown", stage,
    )
    baseline = profile_mapping_get(result, "baseline") if profile_has_mapping(result) else None
    if baseline is None and not (
        profile_has_mapping(result) and profile_mapping_get(result, "degraded") is True
    ):
        baseline = get_extension_baseline(engine, file_path)
    items = profile_mapping_items(result)
    learning = (
        {key: value for key, value in items if key != "baseline"}
        if items is not None else
        {"degraded": True, "unavailable_reason": "profile_update_learning_result_invalid"}
    )
    return {"engine": engine, "engine_context": engine_ctx,
            "extension": normalize_profile_extension(file_path),
            "baseline": baseline, "learning": learning}
__all__ = ("commit_promoted_learning", "update_profile_from_scan_result")
