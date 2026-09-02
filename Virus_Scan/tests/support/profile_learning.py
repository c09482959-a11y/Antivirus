"""Canonical test construction for profile learning decisions and commits."""
from __future__ import annotations

from pathlib import Path
import inspect

from Virus_Scan.models.contracts.learning_authority import (
    LEARNING_AUTHORITY_PROFILE_GATE,
    LEARNING_DISPOSITION_ACCEPTED,
    LearningDecision,
    make_replay_key,
)
from Virus_Scan.models.profiles.commit import commit_promoted_learning
from Virus_Scan.runtime.cluster_state import (
    ClusterStateNotConfigured,
    RuntimeClusterState,
    cluster_state,
    configure_runtime_cluster_state,
)
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


def accepted_learning_decision(
    *, engine: str = "renpy", target_names: tuple[str, ...] = ("profile",),
    observation_id: str | None = None,
) -> LearningDecision:
    if observation_id is None:
        caller = inspect.currentframe()
        caller = caller.f_back if caller is not None else None
        if caller is None:
            observation_id = "test-observation:unknown"
        else:
            observation_id = (
                f"test-observation:{Path(caller.f_code.co_filename).name}:"
                f"{caller.f_code.co_name}:{caller.f_lineno}"
            )
    digest = "a" * 64
    gate_version = "test_gate_v1"
    context_identity = (("learning_baseline_key", engine + "/.test"),)
    replay_key = make_replay_key(
        observation_id=observation_id,
        observation_digest=digest,
        engine=engine,
        context_identity=context_identity,
        verdict="clean",
        risk=0.0,
        scan_integrity_state="complete",
        dangerous_anchor_hits=(),
        triage_block_hits=(),
        disposition=LEARNING_DISPOSITION_ACCEPTED,
        permitted_model_targets=target_names,
        authority=LEARNING_AUTHORITY_PROFILE_GATE,
        reason="test_authorized_learning",
        gate_version=gate_version,
        decision_ordinal=0,
    )
    decision = LearningDecision(
        observation_id=observation_id,
        observation_digest=digest,
        engine=engine,
        context_identity=context_identity,
        verdict="clean",
        risk=0.0,
        scan_integrity_state="complete",
        dangerous_anchor_hits=(),
        triage_block_hits=(),
        disposition=LEARNING_DISPOSITION_ACCEPTED,
        permitted_model_targets=target_names,
        authority=LEARNING_AUTHORITY_PROFILE_GATE,
        reason="test_authorized_learning",
        gate_version=gate_version,
        decision_ordinal=0,
        replay_key=replay_key,
    )
    decision.validate()
    return decision


def accepted_runtime_transaction_result(
    request: object, *, reused: bool = False,
    markov_idempotent: bool = False, temporal_idempotent: bool = False,
) -> dict[str, object]:
    """Build an exact successful transaction publication for replay telemetry tests."""
    decision = getattr(request, "decision", None)
    if type(decision) is not LearningDecision:
        raise TypeError("learning request decision required")
    statuses = {target: "succeeded" for target in decision.permitted_model_targets}
    outputs: dict[str, object] = {}
    if decision.authorizes("markov"):
        outputs["markov"] = {
            "learned": True,
            "idempotent_replay": markov_idempotent,
            "transitions": 1,
        }
    if decision.authorizes("temporal"):
        outputs["temporal"] = {
            "updated": True,
            "idempotent_replay": temporal_idempotent,
            "transitions": 1,
        }
    return {
        "learned": True,
        "promoted": True,
        "persisted": True,
        "transaction_status": "complete",
        "transaction_id": "b" * 64,
        "learning_decision": decision.to_record(),
        "source_record_digest": decision.observation_digest,
        "target_status": statuses,
        "target_outputs": outputs,
        "idempotent_replay": reused,
    }


def promote_clean_observation(
    engine: str,
    file_path: Path,
    tags: tuple[str, ...] | list[str],
    *,
    strings_blob: str = "",
) -> object:
    try:
        cluster_state()
    except ClusterStateNotConfigured:
        configure_runtime_cluster_state(RuntimeClusterState())
    result: object = None
    for ordinal in range(3):
        result = commit_promoted_learning(
            engine,
            file_path,
            physical_tag_evidence(tuple(tags), source_detector="profile_learning_fixture"),
            risk=0.0,
            strings_blob=strings_blob,
            verdict="clean",
            observation_id=f"test:{file_path}:{ordinal}",
        )
    return result


__all__ = ("accepted_learning_decision", "accepted_learning_request", "accepted_runtime_transaction_result", "promote_clean_observation")


def accepted_learning_request(
    file_path: Path,
    *,
    engine: str = "renpy",
    tags: tuple[str, ...] = ("benign_asset",),
    flow: tuple[str, ...] = (),
    observation_id: str = "test-request-observation",
    risk: float = 0.0,
    verdict: str = "clean",
    previous_stage: str = "asset",
    current_stage: str = "runtime",
    scan_integrity: dict[str, object] | None = None,
    ordered_events: tuple[object, ...] = (),
):
    """Build one exact decision-bound transaction request for tests."""
    from Virus_Scan.models.profiles.context import contextual_profile_learning_policy
    from Virus_Scan.models.profiles.learning_decision import build_learning_decision, content_sha256_for_path
    from Virus_Scan.models.profiles.request_contracts import ProfileLearningGateRequest
    from Virus_Scan.models.profiles.transaction_contracts import LearningCommitRequest

    evidence = physical_tag_evidence(
        tuple(tags), source_detector="profile_learning_request_fixture",
        source_stage="authorized_learning_request",
    )
    integrity = dict(scan_integrity or {})
    context_identity = contextual_profile_learning_policy(
        str(file_path), trusted_benign=True, degraded=False,
    )
    validation = {
        "contextual_engine_identity": context_identity.as_record_fields(),
    }
    gate = ProfileLearningGateRequest(
        engine, str(file_path), evidence, risk, "", verdict, (), ordered_events,
        scan_integrity=integrity,
    )
    decision = build_learning_decision(
        gate, observation_id=observation_id, yara_hits=(), behavior_flow=flow,
        previous_stage=previous_stage, current_stage=current_stage,
        learning_allowed=True, reason="test_authorized_learning",
        validation=validation, gate_version="test_gate_v1",
    )
    return LearningCommitRequest(
        decision=decision, engine=engine, file_path=str(file_path),
        content_sha256=content_sha256_for_path(file_path), tag_evidence=evidence, yara_hits=(), risk=risk, strings_blob="",
        verdict=verdict, api_calls=(), ordered_events=ordered_events, behavior_flow=flow,
        previous_stage=previous_stage, current_stage=current_stage,
        validation=validation, scan_integrity=integrity,
    )
