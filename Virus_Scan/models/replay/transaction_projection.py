"""Pure replay telemetry projection from the authoritative learning transaction."""
from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.models.contracts.learning_authority import LearningDecision
from Virus_Scan.models.replay.learning_boundaries import (
    replay_mapping_get,
    replay_mapping_items,
)


def project_runtime_transaction_stats(
    learning_result: Mapping[str, object] | None,
    summary: dict[str, object],
) -> dict[str, object]:
    """Project runtime-learning telemetry from the one authoritative transaction."""
    if replay_mapping_items(learning_result) is None:
        return {
            "runtime_committed": False,
            "reason": "learning_result_unavailable",
            "model_updates_authorized": False,
        }
    if replay_mapping_get(learning_result, "promoted") is not True:
        return {
            "runtime_committed": False,
            "reason": "profile_promotion_required",
            "model_updates_authorized": False,
        }
    raw_decision = replay_mapping_get(learning_result, "learning_decision")
    if type(raw_decision) is not dict:
        return {
            "runtime_committed": False,
            "reason": "learning_decision_required",
            "model_updates_authorized": False,
        }
    try:
        decision = LearningDecision.from_record(raw_decision)
    except ValueError:
        return {
            "runtime_committed": False,
            "reason": "learning_decision_invalid",
            "model_updates_authorized": False,
        }
    source_digest = replay_mapping_get(learning_result, "source_record_digest")
    if type(source_digest) is not str or source_digest != decision.observation_digest:
        return {
            "runtime_committed": False,
            "reason": "source_record_digest_mismatch",
            "model_updates_authorized": False,
        }
    authorized = tuple(
        target for target in ("markov", "temporal")
        if decision.authorizes(target)
    )
    if not authorized:
        return {
            "runtime_committed": False,
            "reason": "runtime_model_learning_not_authorized",
            "model_updates_authorized": False,
            "source_record_digest": decision.observation_digest,
        }
    if replay_mapping_get(learning_result, "persisted") is not True:
        return {
            "runtime_committed": False,
            "reason": "learning_transaction_not_persisted",
            "model_updates_authorized": True,
            "source_record_digest": decision.observation_digest,
        }
    if replay_mapping_get(learning_result, "transaction_status") != "complete":
        return {
            "runtime_committed": False,
            "reason": "learning_transaction_incomplete",
            "model_updates_authorized": True,
            "source_record_digest": decision.observation_digest,
        }
    target_status = replay_mapping_get(learning_result, "target_status")
    target_outputs = replay_mapping_get(learning_result, "target_outputs")
    if replay_mapping_items(target_status) is None:
        return {
            "runtime_committed": False,
            "reason": "runtime_target_status_unavailable",
            "model_updates_authorized": True,
            "source_record_digest": decision.observation_digest,
        }
    if replay_mapping_items(target_outputs) is None:
        return {
            "runtime_committed": False,
            "reason": "runtime_target_output_unavailable",
            "model_updates_authorized": True,
            "source_record_digest": decision.observation_digest,
        }

    succeeded: dict[str, bool] = {"markov": False, "temporal": False}
    idempotent: dict[str, bool] = {"markov": True, "temporal": True}
    for target in authorized:
        if replay_mapping_get(target_status, target) != "succeeded":
            return {
                "runtime_committed": False,
                "reason": "runtime_target_status_incomplete:" + target,
                "model_updates_authorized": True,
                "source_record_digest": decision.observation_digest,
            }
        output = replay_mapping_get(target_outputs, target)
        if replay_mapping_items(output) is None:
            return {
                "runtime_committed": False,
                "reason": "runtime_target_output_unavailable:" + target,
                "model_updates_authorized": True,
                "source_record_digest": decision.observation_digest,
            }
        success_key = "learned" if target == "markov" else "updated"
        if replay_mapping_get(output, success_key) is not True:
            return {
                "runtime_committed": False,
                "reason": "runtime_target_output_incomplete:" + target,
                "model_updates_authorized": True,
                "source_record_digest": decision.observation_digest,
            }
        succeeded[target] = True
        idempotent[target] = replay_mapping_get(output, "idempotent_replay") is True

    reused_transaction = (
        replay_mapping_get(learning_result, "idempotent_replay") is True
        or replay_mapping_get(learning_result, "content_deduplicated") is True
    )
    markov_mutated = (
        succeeded["markov"] and not reused_transaction and not idempotent["markov"]
    )
    temporal_mutated = (
        succeeded["temporal"] and not reused_transaction and not idempotent["temporal"]
    )
    summary["runtime"] = 1
    return {
        "runtime_committed": True,
        "reason": None,
        "markov": succeeded["markov"],
        "markov_mutated": markov_mutated,
        "temporal": succeeded["temporal"],
        "temporal_mutated": temporal_mutated,
        "idempotent_replay": reused_transaction or all(
            idempotent[target] for target in authorized
        ),
        "model_updates_authorized": True,
        "source_record_digest": decision.observation_digest,
        "transaction_id": replay_mapping_get(learning_result, "transaction_id"),
    }



__all__ = ("project_runtime_transaction_stats",)
