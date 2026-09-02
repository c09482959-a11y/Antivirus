"""Bounded idempotent persistence owner for learning-decision summaries."""
from __future__ import annotations

from typing import Final

from Virus_Scan.models.contracts.learning_authority import (
    CANONICAL_MODEL_TARGETS,
    LearningDecision,
)

PROFILE_DECISION_HISTORY_SCHEMA_VERSION: Final[str] = "profile_decision_history_v1"
_MAX_DECISION_HISTORY_RECORDS: Final[int] = 1024


def default_profile_decision_history() -> dict[str, object]:
    return {
        "schema_version": PROFILE_DECISION_HISTORY_SCHEMA_VERSION,
        "total": 0,
        "accepted": 0,
        "rejected": 0,
        "quarantined": 0,
        "records": {},
    }


def validate_profile_decision_history(value: object) -> bool:
    if type(value) is not dict:
        raise ValueError("profile_decision_history_invalid")
    if value.get("schema_version") != PROFILE_DECISION_HISTORY_SCHEMA_VERSION:
        raise ValueError("profile_decision_history_schema_invalid")
    records = value.get("records")
    if type(records) is not dict or len(records) > _MAX_DECISION_HISTORY_RECORDS:
        raise ValueError("profile_decision_history_records_invalid")
    counts = tuple(value.get(key) for key in ("total", "accepted", "rejected", "quarantined"))
    if any(type(count) is not int or isinstance(count, bool) or count < 0 for count in counts):
        raise ValueError("profile_decision_history_count_invalid")
    if counts[0] != sum(counts[1:]) or counts[0] != len(records):
        raise ValueError("profile_decision_history_count_mismatch")
    for replay_key, record in records.items():
        if type(replay_key) is not str or type(record) is not dict:
            raise ValueError("profile_decision_history_record_invalid")
        if record.get("replay_key") != replay_key:
            raise ValueError("profile_decision_history_identity_invalid")
        disposition = record.get("disposition")
        if disposition not in {"accepted", "rejected", "quarantined"}:
            raise ValueError("profile_decision_history_disposition_invalid")
        ordinal = record.get("decision_ordinal")
        if type(ordinal) is not int or isinstance(ordinal, bool) or ordinal < 0:
            raise ValueError("profile_decision_history_ordinal_invalid")
        if type(record.get("observation_id")) is not str or not record["observation_id"]:
            raise ValueError("profile_decision_history_identity_invalid")
        digest = record.get("observation_digest")
        if (
            type(digest) is not str or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            raise ValueError("profile_decision_history_identity_invalid")
        if type(record.get("reason")) is not str or not record["reason"]:
            raise ValueError("profile_decision_history_reason_invalid")
        targets = record.get("permitted_model_targets")
        if type(targets) is not list:
            raise ValueError("profile_decision_history_targets_invalid")
        canonical = [target for target in CANONICAL_MODEL_TARGETS if target in targets]
        if targets != canonical or (disposition != "accepted" and targets):
            raise ValueError("profile_decision_history_targets_invalid")
    return True


def record_profile_learning_decision(
    history: object, decision: LearningDecision,
) -> dict[str, object]:
    validate_profile_decision_history(history)
    records = history["records"]
    existing = records.get(decision.replay_key)
    summary = {
        "replay_key": decision.replay_key,
        "observation_id": decision.observation_id,
        "observation_digest": decision.observation_digest,
        "disposition": decision.disposition,
        "reason": decision.reason,
        "decision_ordinal": decision.decision_ordinal,
        "permitted_model_targets": list(decision.permitted_model_targets),
    }
    if existing is not None:
        if existing != summary:
            raise ValueError("profile_decision_history_identity_collision")
        return history
    records[decision.replay_key] = summary
    history["total"] += 1
    history[decision.disposition] += 1
    if len(records) > _MAX_DECISION_HISTORY_RECORDS:
        ranked = sorted(
            (record["decision_ordinal"], key)
            for key, record in records.items()
        )
        for _ordinal, key in ranked[:-_MAX_DECISION_HISTORY_RECORDS]:
            disposition = records[key]["disposition"]
            records.pop(key)
            history["total"] -= 1
            history[disposition] -= 1
    validate_profile_decision_history(history)
    return history


__all__ = (
    "PROFILE_DECISION_HISTORY_SCHEMA_VERSION",
    "default_profile_decision_history",
    "record_profile_learning_decision",
    "validate_profile_decision_history",
)
