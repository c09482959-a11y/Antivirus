from dataclasses import FrozenInstanceError

import pytest

from Virus_Scan.models.contracts.learning_authority import (
    CANONICAL_MODEL_TARGETS,
    LEARNING_DISPOSITION_ACCEPTED,
    LEARNING_DISPOSITION_QUARANTINED,
    LearningDecision,
)
from Virus_Scan.models.profiles.learning_decision import build_learning_decision
from Virus_Scan.models.profiles.request_contracts import ProfileLearningGateRequest


def _validation(**extra: object) -> dict[str, object]:
    data: dict[str, object] = {
        "contextual_engine_identity": {
            "baseline_key": ".rpy|engine=renpy",
            "learning_baseline_key": ".rpy|engine=renpy",
        },
        "dangerous_anchor_hits": (),
        "triage_block_hits": (),
    }
    data.update(extra)
    return data


def _decision(**extra: object) -> LearningDecision:
    request_fields: dict[str, object] = {
        "engine": "renpy",
        "file_path": "game.rpy",
        "tags": ("renpy_script",),
        "risk": 0.0,
        "strings_blob": "",
        "verdict": "clean",
        "scan_integrity": {"allow_learning": True},
    }
    decision_fields: dict[str, object] = {
        "observation_id": "job:2636.10",
        "yara_hits": (),
        "behavior_flow": ("script", "execute"),
        "previous_stage": "unknown",
        "current_stage": "script",
        "learning_allowed": True,
        "reason": "trusted_benign_learning_allowed",
        "validation": _validation(),
        "gate_version": "gate-v1",
        "decision_ordinal": 1,
    }
    for key, value in extra.items():
        (request_fields if key in request_fields else decision_fields)[key] = value
    request = ProfileLearningGateRequest(**request_fields)
    return build_learning_decision(request, **decision_fields)


def test_phase2_decision_is_frozen_digest_bound_and_round_trips() -> None:
    decision = _decision()
    assert decision.disposition == LEARNING_DISPOSITION_ACCEPTED
    assert decision.permitted_model_targets == CANONICAL_MODEL_TARGETS
    assert all(decision.authorizes(target) for target in CANONICAL_MODEL_TARGETS)
    assert LearningDecision.from_record(decision.to_record()) == decision
    with pytest.raises(FrozenInstanceError):
        decision.reason = "changed"  # type: ignore[misc]
    forged = decision.to_record()
    forged["replay_key"] = "0" * 64
    with pytest.raises(ValueError, match="replay key mismatch"):
        LearningDecision.from_record(forged)
    forged_targets = decision.to_record()
    forged_targets["permitted_model_targets"] = ["profile"]
    with pytest.raises(ValueError, match="replay key mismatch"):
        LearningDecision.from_record(forged_targets)


def test_phase2_nonclean_or_dangerous_evidence_cannot_authorize_targets() -> None:
    nonclean = _decision(verdict="malicious", learning_allowed=False, reason="verdict_not_clean")
    assert nonclean.permitted_model_targets == ()
    assert not nonclean.authorizes("profile")
    dangerous = _decision(
        validation=_validation(dangerous_anchor_hits=("credential_dump",)),
        learning_allowed=True,
    )
    assert dangerous.disposition == LEARNING_DISPOSITION_QUARANTINED
    assert dangerous.permitted_model_targets == ()


def test_phase2_target_selection_requires_a_real_markov_transition() -> None:
    decision = _decision(behavior_flow=("script",))
    assert decision.permitted_model_targets == (
        "profile", "temporal", "filetype", "clustering",
    )
    assert decision.authorizes("temporal")
    assert not decision.authorizes("markov")


def test_phase2_observation_digest_preserves_behavior_order() -> None:
    forward = _decision(behavior_flow=("download", "execute"))
    reverse = _decision(behavior_flow=("execute", "download"))
    assert forward.observation_digest != reverse.observation_digest
    assert forward.replay_key != reverse.replay_key
