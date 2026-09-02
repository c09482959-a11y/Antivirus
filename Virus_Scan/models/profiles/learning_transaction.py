"""Single persisted transaction owner for all authorized online model updates."""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Final

from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.models.api.clustering_contracts import (
    assign_cluster_with_context_tags,
    build_learning_feature_vector,
    load_cluster_runtime_model_record,
)
from Virus_Scan.models.api.markov_contracts import update_markov_model
from Virus_Scan.models.profiles.temporal_target import apply_temporal_learning_target
from Virus_Scan.models.contracts.learning_authority import (
    LearningDecision,
    learning_authorization_failure,
)
from Virus_Scan.models.profiles.contamination import (
    ContaminationPlan,
    preflight_learning_contamination,
)
from Virus_Scan.models.profiles.decision_history import (
    record_profile_learning_decision,
)
from Virus_Scan.models.profiles.extension_learning import apply_extension_learning_decision
from Virus_Scan.models.profiles.learning import behavior_vector_from_scan
from Virus_Scan.models.profiles.persistence import (
    PROFILE_FILE_LOCK,
    load_engine_profile,
    profile_persistence_state_owner,
    profile_update_marker,
)
from Virus_Scan.models.profiles.persistence_snapshot import (
    persisted_engine_profile_snapshot,
    persisted_staged_benign_snapshot,
)
from Virus_Scan.models.profiles.transaction_contracts import LearningCommitRequest
from Virus_Scan.models.profiles.transaction_state import (
    authorized_transaction_target_order,
    prune_completed_transactions,
    refresh_transaction_status,
    validate_persisted_transaction,
)
from Virus_Scan.models.profiles.schema_versions import (
    PROFILE_LEARNING_TRANSACTION_SCHEMA_VERSION,
)
from Virus_Scan.runtime.model_state import runtime_model_state_to_json
from Virus_Scan.runtime import model_state as runtime_model_state
from Virus_Scan.runtime.api import load_runtime_model_baselines
from Virus_Scan.runtime.model_state import apply_filetype_baseline_once
from Virus_Scan.runtime.runtime_flags import runtime_flag_clear
from Virus_Scan.storage import authoritative_model_state, learning_candidate_store

TRANSACTION_SCHEMA_VERSION: Final[str] = PROFILE_LEARNING_TRANSACTION_SCHEMA_VERSION


def _target_record() -> dict[str, object]:
    return {"status": "pending", "attempts": 0, "reason": "", "output": {}}


def _new_transaction(
    request: LearningCommitRequest, plan: ContaminationPlan,
) -> dict[str, object]:
    decision = request.decision
    target_order = authorized_transaction_target_order(decision)
    targets = {target: _target_record() for target in target_order}
    return {
        "schema_version": TRANSACTION_SCHEMA_VERSION,
        "replay_key": decision.replay_key,
        "observation_id": decision.observation_id,
        "observation_digest": decision.observation_digest,
        "content_sha256": request.content_sha256,
        "artifact_instance": request.file_path,
        "decision_ordinal": decision.decision_ordinal,
        "decision": decision.to_record(),
        "context_key": plan.context_key,
        "diversity_key": plan.diversity_key,
        "target_order": list(target_order),
        "targets": targets,
        "status": "pending",
        "completed_targets": 0,
        "failed_targets": 0,
    }


def _transaction_store(profile: dict[str, object]) -> dict[str, object]:
    model_state = profile.get("model_state")
    if type(model_state) is not dict:
        raise ValueError("profile model_state unavailable")
    store = model_state.get("learning_transactions")
    if type(store) is not dict:
        raise ValueError("profile learning transaction store unavailable")
    return store



def _transaction_for(
    profile: dict[str, object], request: LearningCommitRequest,
    plan: ContaminationPlan | None,
) -> tuple[dict[str, object] | None, str | None]:
    store = _transaction_store(profile)
    existing = store.get(request.decision.replay_key)
    if existing is not None:
        try:
            persisted_decision = validate_persisted_transaction(
                request.decision.replay_key, existing,
            )
        except ValueError as exc:
            return None, str(exc).replace(" ", "_")
        if persisted_decision != request.decision:
            return None, "learning_transaction_decision_mismatch"
        return existing, None
    if plan is None or not plan.accepted:
        return None, "learning_transaction_not_found"
    transaction = _new_transaction(request, plan)
    store[request.decision.replay_key] = transaction
    prune_completed_transactions(store)
    return transaction, None


def _mapping_flag(result: object, key: str) -> bool:
    return isinstance(result, Mapping) and result.get(key) is True


def _mapping_reason(result: object, default: str) -> str:
    if isinstance(result, Mapping):
        reason = result.get("reason") or result.get("unavailable_reason")
        if type(reason) is str and reason != "":
            return reason
    return default


def _filetype_target(request: LearningCommitRequest) -> dict[str, object]:
    reason = learning_authorization_failure(request.decision, "filetype")
    if reason is not None:
        return {"updated": False, "reason": reason}
    extension = get_scan_extension(request.file_path) or "<no_ext>"
    applied = apply_filetype_baseline_once(
        request.decision.replay_key, request.decision.decision_ordinal,
        extension, request.behavior_flow,
        mark_dirty=runtime_model_state.mark_runtime_models_dirty,
    )
    return {
        "updated": True, "extension": extension,
        "idempotent_replay": not applied,
    }


def _cluster_target(request: LearningCommitRequest, vector: object) -> object:
    return assign_cluster_with_context_tags(
        request.file_path,
        vector,
        tags=request.tag_evidence,
        engine_context={request.engine: 1.0},
        learning_decision=request.decision,
    )


def _execute_target(
    target: str,
    request: LearningCommitRequest,
    profile: dict[str, object],
    profile_vector: object,
    cluster_vector: object,
    diversity_key: str,
) -> tuple[bool, object, str]:
    if target == "profile":
        result = apply_extension_learning_decision(
            profile, request, profile_vector, diversity_key=diversity_key,
        )
        return _mapping_flag(result, "updated"), result, _mapping_reason(result, "profile_target_failed")
    if target == "markov":
        result = update_markov_model(
            request.previous_stage,
            request.behavior_flow,
            request.current_stage,
            learning_decision=request.decision,
        )
        return _mapping_flag(result, "learned"), result, _mapping_reason(result, "markov_target_failed")
    if target == "temporal":
        result = apply_temporal_learning_target(profile, request)
        return _mapping_flag(result, "updated"), result, _mapping_reason(result, "temporal_target_failed")
    if target == "filetype":
        result = _filetype_target(request)
        return _mapping_flag(result, "updated"), result, _mapping_reason(result, "filetype_target_failed")
    if target == "clustering":
        result = _cluster_target(request, cluster_vector)
        if type(result) is str and result != "":
            return True, {"cluster_id": result}, ""
        return _mapping_flag(result, "assigned"), result, _mapping_reason(result, "clustering_target_failed")
    return False, {"reason": "learning_target_invalid"}, "learning_target_invalid"


def _output_summary(output: object) -> dict[str, object]:
    if not isinstance(output, Mapping):
        return {}
    allowed = (
        "updated", "learned", "assigned", "reason", "unavailable_reason",
        "extension", "cluster_id", "idempotent_replay", "transitions",
    )
    return {
        key: value for key in allowed
        if type(value := output.get(key)) in (str, int, float, bool)
        or value is None
    }


def _publication(transaction: dict[str, object], outputs: dict[str, object]) -> dict[str, object]:
    targets = transaction.get("targets", {})
    target_items = dict.items(targets) if type(targets) is dict else ()
    statuses = {
        target: state.get("status", "invalid") if type(state) is dict else "invalid"
        for target, state in target_items
    }
    complete = bool(statuses) and all(status == "succeeded" for status in statuses.values())
    partial = any(status == "failed" for status in statuses.values())
    publication = {
        "learned": complete,
        "reason": (
            "promoted_clean_learning_committed" if complete
            else "learning_transaction_partial" if partial
            else "learning_transaction_pending"
        ),
        "promoted": True,
        "transaction_status": transaction.get("status"),
        "replay_key": transaction.get("replay_key"),
        "target_status": statuses,
        "target_outputs": outputs,
    }
    profile_output = outputs.get("profile")
    if isinstance(profile_output, Mapping) and isinstance(profile_output.get("baseline"), Mapping):
        publication["baseline"] = profile_output["baseline"]
    return publication


def _restore_owned_state(
    profile: dict[str, object], profile_before: dict[str, object],
    runtime_before: Mapping[str, object],
) -> str | None:
    """Restore every in-memory owner after an uncommitted target mutation."""
    profile.clear()
    profile.update(deepcopy(profile_before))
    runtime_result = load_runtime_model_baselines(runtime_before)
    if runtime_result.get("loaded") is not True:
        return str(runtime_result.get("reason") or "runtime_model_restore_failed")
    cluster_result = load_cluster_runtime_model_record(runtime_before.get("cluster_state"))
    if cluster_result is not True:
        return "cluster_model_restore_failed"
    runtime_flag_clear("runtime_model_state_dirty")
    return None


def _stored_transaction_publication(
    profile: dict[str, object], replay_key: str, *, content_deduplicated: bool,
) -> dict[str, object] | None:
    store = _transaction_store(profile)
    transaction = store.get(replay_key)
    if type(transaction) is not dict:
        return None
    try:
        validate_persisted_transaction(replay_key, transaction)
    except ValueError:
        return None
    if transaction.get("status") != "complete":
        return None
    stored_targets = transaction.get("targets", {})
    stored_outputs = {
        target: state.get("output", {})
        for target, state in dict.items(stored_targets)
        if type(state) is dict
    } if type(stored_targets) is dict else {}
    publication = _publication(transaction, stored_outputs)
    publication["idempotent_replay"] = True
    if content_deduplicated:
        publication["content_deduplicated"] = True
        publication["source_replay_key"] = replay_key
    return publication


def _occurrence_record(request: LearningCommitRequest) -> dict[str, object]:
    return {
        "engine": request.engine,
        "profile_scope": "default",
        "content_sha256": request.content_sha256,
        "artifact_instance": request.file_path,
        "context_identity": dict(request.decision.context_identity),
        "decision_ordinal": request.decision.decision_ordinal,
    }


def _publish_staged_snapshot(staged_snapshot: dict[str, object]) -> None:
    state = profile_persistence_state_owner()
    state.set_staged_cache(deepcopy(staged_snapshot), dirty=False)
    state.reset_staged_update_count()


def _commit_content_occurrence(
    request: LearningCommitRequest, staged_store: dict[str, object],
) -> str:
    staged_snapshot = persisted_staged_benign_snapshot(staged_store)
    transaction_id = authoritative_model_state().transaction_identity(
        transaction_kind="content_occurrence", replay_key=request.decision.replay_key,
    )
    learning_candidate_store().commit_staged_store(
        staged_snapshot, transaction_kind="content_occurrence_candidate_state",
        replay_key=request.decision.replay_key,
        related_authoritative_transaction_id=transaction_id,
    )
    committed_id = authoritative_model_state().commit(
        occurrences=(_occurrence_record(request),),
        transaction_kind="content_occurrence",
        replay_key=request.decision.replay_key,
    )
    if committed_id != transaction_id:
        raise ValueError("authoritative_transaction_identity_changed")
    _publish_staged_snapshot(staged_snapshot)
    return committed_id


def _commit_learning_state(
    *, request: LearningCommitRequest, profile: dict[str, object],
    staged_store: dict[str, object], transaction_kind: str,
) -> str:
    transaction = _transaction_store(profile).get(request.decision.replay_key)
    if type(transaction) is dict and transaction.get("status") == "complete":
        transaction["authoritative_transaction_id"] = (
            authoritative_model_state().transaction_identity(
                transaction_kind=transaction_kind,
                replay_key=request.decision.replay_key,
            )
        )
    profile["updated"] = profile_update_marker(profile)
    profile_snapshot = persisted_engine_profile_snapshot(
        profile, expected_engine=request.engine,
    )
    runtime_snapshot = runtime_model_state_to_json()
    if type(runtime_snapshot) is not dict:
        raise ValueError("runtime_model_snapshot_invalid")
    staged_snapshot = persisted_staged_benign_snapshot(staged_store)
    transaction_id = authoritative_model_state().transaction_identity(
        transaction_kind=transaction_kind, replay_key=request.decision.replay_key,
    )
    learning_candidate_store().commit_staged_store(
        staged_snapshot, transaction_kind=transaction_kind + "_candidate_state",
        replay_key=request.decision.replay_key,
        related_authoritative_transaction_id=transaction_id,
    )
    committed_id = authoritative_model_state().commit(
        profiles=(profile_snapshot,),
        runtime_snapshot=runtime_snapshot,
        occurrences=(_occurrence_record(request),),
        transaction_kind=transaction_kind,
        replay_key=request.decision.replay_key,
    )
    if committed_id != transaction_id:
        raise ValueError("authoritative_transaction_identity_changed")
    state = profile_persistence_state_owner()
    state.clear_profile_dirty((request.engine,))
    state.reset_profile_update_count()
    _publish_staged_snapshot(staged_snapshot)
    runtime_flag_clear("runtime_model_state_dirty")
    return committed_id


def execute_learning_transaction(
    request: LearningCommitRequest, staged_store: dict[str, object],
) -> dict[str, object]:
    """Commit one accepted learning decision across every model owner atomically."""
    request.validate()
    staged_snapshot_input = persisted_staged_benign_snapshot(staged_store)
    with PROFILE_FILE_LOCK:
        profile = load_engine_profile(request.engine)
        if type(profile) is not dict:
            return {"learned": False, "reason": "profile_state_unavailable", "promoted": True}
        model_state = profile.get("model_state")
        if type(model_state) is not dict:
            return {"learned": False, "reason": "profile_model_state_unavailable", "promoted": True}

        direct_transaction, direct_reason = _transaction_for(profile, request, None)
        if direct_transaction is not None:
            existing = _stored_transaction_publication(
                profile, request.decision.replay_key, content_deduplicated=False,
            )
            if existing is not None:
                return existing
            return {
                "learned": False,
                "reason": "learning_transaction_incomplete_persisted_state",
                "promoted": True,
            }
        if direct_reason != "learning_transaction_not_found":
            return {"learned": False, "reason": direct_reason, "promoted": True}

        if request.content_sha256:
            source_replay_key = authoritative_model_state().find_learning_replay_key(
                engine=request.engine,
                content_sha256=request.content_sha256,
                context_identity=dict(request.decision.context_identity),
                observation_digest=request.decision.observation_digest,
            )
            if source_replay_key is not None:
                publication = _stored_transaction_publication(
                    profile, source_replay_key, content_deduplicated=True,
                )
                if publication is None:
                    return {
                        "learned": False,
                        "reason": "content_learning_identity_inconsistent",
                        "promoted": True,
                    }
                try:
                    transaction_id = _commit_content_occurrence(
                        request, staged_snapshot_input,
                    )
                except RECOVERABLE_RUNTIME_ERRORS as exc:
                    return {
                        "learned": False,
                        "reason": "content_occurrence_commit_failed",
                        "error_type": type(exc).__name__,
                        "promoted": True,
                    }
                publication["replay_key"] = request.decision.replay_key
                publication["transaction_id"] = transaction_id
                publication["persisted"] = True
                return publication

        profile_before = deepcopy(profile)
        runtime_before = runtime_model_state_to_json()
        if type(runtime_before) is not dict:
            return {
                "learned": False, "reason": "runtime_model_snapshot_invalid",
                "promoted": True,
            }
        try:
            record_profile_learning_decision(
                model_state.get("decision_history"), request.decision,
            )
        except ValueError as exc:
            profile.clear()
            profile.update(profile_before)
            return {"learned": False, "reason": str(exc), "promoted": True}

        transaction, transaction_reason = _transaction_for(profile, request, None)
        if transaction is not None:
            profile.clear()
            profile.update(profile_before)
            return {
                "learned": False,
                "reason": "learning_transaction_incomplete_persisted_state",
                "promoted": True,
            }
        if transaction_reason != "learning_transaction_not_found":
            profile.clear()
            profile.update(profile_before)
            return {"learned": False, "reason": transaction_reason, "promoted": True}

        profile_vector = behavior_vector_from_scan(
            request.engine, request.file_path, request.tag_evidence,
            api_calls=request.api_calls, ordered_events=request.ordered_events,
        )
        try:
            plan = preflight_learning_contamination(profile, request, profile_vector)
        except ValueError as exc:
            profile.clear()
            profile.update(profile_before)
            return {"learned": False, "reason": str(exc), "promoted": True}
        if not plan.accepted:
            try:
                transaction_id = _commit_learning_state(
                    request=request, profile=profile,
                    staged_store=staged_snapshot_input,
                    transaction_kind="learning_quarantine",
                )
            except RECOVERABLE_RUNTIME_ERRORS as exc:
                restore_reason = _restore_owned_state(profile, profile_before, runtime_before)
                return {
                    "learned": False,
                    "reason": restore_reason or "learning_quarantine_commit_failed",
                    "error_type": type(exc).__name__,
                    "promoted": True,
                }
            return {
                "learned": False, "reason": plan.reason, "promoted": True,
                "disposition": "quarantined",
                "context_key": plan.context_key,
                "drift_dimensions": plan.drift_dimensions,
                "transaction_id": transaction_id,
            }

        transaction, transaction_reason = _transaction_for(profile, request, plan)
        if transaction is None:
            profile.clear()
            profile.update(profile_before)
            return {"learned": False, "reason": transaction_reason, "promoted": True}
        diversity_key = transaction.get("diversity_key")
        if type(diversity_key) is not str or diversity_key == "":
            profile.clear()
            profile.update(profile_before)
            return {
                "learned": False,
                "reason": "learning_transaction_contamination_plan_invalid",
                "promoted": True,
            }
        cluster_vector = build_learning_feature_vector(
            request.tag_evidence, {request.engine: 1.0},
        )
        outputs: dict[str, object] = {}
        targets = transaction.get("targets", {})
        if type(targets) is not dict:
            profile.clear()
            profile.update(profile_before)
            return {"learned": False, "reason": "learning_transaction_targets_invalid", "promoted": True}

        for target in transaction.get("target_order", ()):
            state = targets.get(target)
            if type(state) is not dict:
                succeeded, output, reason = False, {}, "learning_target_state_invalid"
            else:
                state["status"] = "in_progress"
                state["attempts"] = int(state.get("attempts", 0)) + 1
                state["reason"] = ""
                state["output"] = {}
                try:
                    succeeded, output, reason = _execute_target(
                        target, request, profile, profile_vector,
                        cluster_vector, diversity_key,
                    )
                except RECOVERABLE_RUNTIME_ERRORS as exc:
                    succeeded, output, reason = False, {}, type(exc).__name__
            outputs[target] = output
            if type(state) is dict:
                state["status"] = "succeeded" if succeeded else "failed"
                state["reason"] = "" if succeeded else reason
                state["output"] = _output_summary(output)
            refresh_transaction_status(transaction)
            if not succeeded:
                restore_reason = _restore_owned_state(profile, profile_before, runtime_before)
                publication = _publication(transaction, outputs)
                publication.update({
                    "learned": False,
                    "reason": restore_reason or "learning_transaction_rolled_back",
                    "transaction_status": "rolled_back",
                    "persisted": False,
                    "failed_target": target,
                })
                return publication

        refresh_transaction_status(transaction)
        try:
            transaction_id = _commit_learning_state(
                request=request, profile=profile,
                staged_store=staged_snapshot_input,
                transaction_kind="learning_commit",
            )
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            restore_reason = _restore_owned_state(profile, profile_before, runtime_before)
            publication = _publication(transaction, outputs)
            publication.update({
                "learned": False,
                "reason": restore_reason or "learning_transaction_commit_failed",
                "transaction_status": "rolled_back",
                "persisted": False,
                "error_type": type(exc).__name__,
            })
            return publication
        publication = _publication(transaction, outputs)
        publication["transaction_id"] = transaction_id
        publication["persisted"] = True
        return publication


__all__ = (
    "TRANSACTION_SCHEMA_VERSION",
    "execute_learning_transaction",
)
