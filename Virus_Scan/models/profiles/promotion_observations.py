"""Bounded persisted observation-ledger mechanics for profile promotion."""
from __future__ import annotations

from typing import Final

from Virus_Scan.models.profiles.transaction_contracts import LearningCommitRequest

OBSERVATION_LEDGER_SCHEMA_VERSION: Final[str] = "profile_learning_observation_ledger_v1"
_MAX_OBSERVATION_LEDGER_ENTRIES: Final[int] = 4096


def new_observation_ledger() -> dict[str, object]:
    return {
        "schema_version": OBSERVATION_LEDGER_SCHEMA_VERSION,
        "entries": {},
    }


def validate_observation_ledger(value: object) -> bool:
    """Validate the exact persisted staged-observation ledger schema."""
    if type(value) is not dict:
        raise ValueError("learning observation ledger invalid")
    if value.get("schema_version") != OBSERVATION_LEDGER_SCHEMA_VERSION:
        raise ValueError("learning observation ledger schema invalid")
    entries = value.get("entries")
    if type(entries) is not dict or len(entries) > _MAX_OBSERVATION_LEDGER_ENTRIES:
        raise ValueError("learning observation ledger entries invalid")
    for observation_id, entry in entries.items():
        if type(observation_id) is not str or observation_id == "" or type(entry) is not dict:
            raise ValueError("learning observation record invalid")
        if entry.get("observation_id") != observation_id:
            raise ValueError("learning observation identity invalid")
        for field in ("observation_digest", "replay_key"):
            value_text = entry.get(field)
            if type(value_text) is not str or len(value_text) != 64:
                raise ValueError("learning observation identity invalid")
        ordinal = entry.get("decision_ordinal")
        if type(ordinal) is not int or isinstance(ordinal, bool) or ordinal < 0:
            raise ValueError("learning observation ordinal invalid")
        status = entry.get("status")
        if status not in {"pending", "staged", "promoted", "rejected"}:
            raise ValueError("learning observation status invalid")
        if type(entry.get("reason")) is not str or type(entry.get("candidate_key")) is not str:
            raise ValueError("learning observation record invalid")
        if type(entry.get("promoted")) is not bool:
            raise ValueError("learning observation record invalid")
        if entry["promoted"] is not (status == "promoted"):
            raise ValueError("learning observation promotion state invalid")
    return True


def _ledger(store: dict[str, object]) -> dict[str, object]:
    raw = store.get("observation_ledger")
    validate_observation_ledger(raw)
    assert type(raw) is dict
    return raw


def _prune(entries: dict[str, object], preserve: str) -> None:
    if len(entries) <= _MAX_OBSERVATION_LEDGER_ENTRIES:
        return
    ranked: list[tuple[int, str]] = []
    for observation_id, raw in dict.items(entries):
        ordinal = raw.get("decision_ordinal", 0) if type(raw) is dict else 0
        ranked.append((ordinal if type(ordinal) is int else 0, observation_id))
    keep = {
        observation_id
        for _ordinal, observation_id in sorted(ranked, reverse=True)[
            :_MAX_OBSERVATION_LEDGER_ENTRIES
        ]
    }
    keep.add(preserve)
    for observation_id in tuple(entries):
        if observation_id not in keep:
            entries.pop(observation_id, None)


def begin_observation(
    store: dict[str, object], request: LearningCommitRequest,
) -> tuple[str, dict[str, object] | None, str | None]:
    """Create or resolve one exact observation identity."""
    ledger = _ledger(store)
    entries = ledger["entries"]
    assert type(entries) is dict
    decision = request.decision
    existing = entries.get(decision.observation_id)
    if existing is not None:
        if type(existing) is not dict:
            return "invalid", None, "learning_observation_record_invalid"
        if (
            existing.get("observation_digest") != decision.observation_digest
            or existing.get("replay_key") != decision.replay_key
        ):
            return "collision", None, "learning_observation_identity_collision"
        return "replay", existing, None
    entry: dict[str, object] = {
        "observation_id": decision.observation_id,
        "observation_digest": decision.observation_digest,
        "replay_key": decision.replay_key,
        "decision_ordinal": decision.decision_ordinal,
        "status": "pending",
        "candidate_key": "",
        "reason": "",
        "promoted": False,
    }
    entries[decision.observation_id] = entry
    _prune(entries, decision.observation_id)
    return "new", entry, None


def update_observation(
    store: dict[str, object],
    request: LearningCommitRequest,
    *,
    status: str,
    reason: str,
    candidate_key: str = "",
    promoted: bool = False,
) -> dict[str, object]:
    """Update only the exact ledger record created for the request."""
    ledger = _ledger(store)
    entries = ledger["entries"]
    assert type(entries) is dict
    entry = entries.get(request.decision.observation_id)
    if type(entry) is not dict:
        raise ValueError("learning observation record unavailable")
    if (
        entry.get("observation_digest") != request.decision.observation_digest
        or entry.get("replay_key") != request.decision.replay_key
    ):
        raise ValueError("learning observation identity collision")
    entry["status"] = status
    entry["reason"] = reason
    entry["candidate_key"] = candidate_key
    entry["promoted"] = promoted
    return entry


__all__ = (
    "OBSERVATION_LEDGER_SCHEMA_VERSION",
    "begin_observation",
    "new_observation_ledger",
    "validate_observation_ledger",
    "update_observation",
)
