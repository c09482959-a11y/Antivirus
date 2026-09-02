"""Canonical SQLite profile-corruption policy and evidence owner."""
from __future__ import annotations

import logging

from Virus_Scan.runtime.config_state import get_profile_corruption_policy
from Virus_Scan.runtime.immutable_core import freeze_runtime_value
from Virus_Scan.models.profiles.corruption import profile_corruption_evidence
from Virus_Scan.models.profiles.schema import ProfileSchemaInvariantError
from Virus_Scan.storage import authoritative_model_state


def profile_corruption_events_snapshot() -> tuple[object, ...]:
    """Return immutable durable corruption events from the model database."""
    return tuple(
        freeze_runtime_value(event)
        for event in authoritative_model_state().read_profile_corruption_events()
    )


def _database_profile_identity(engine: str) -> str:
    return authoritative_model_state().model_database_path() + "#profile/" + engine


def _record_for_policy(
    engine: str, reason: object, *, profile: object, policy: str,
    quarantined: bool, scan_continued: bool,
) -> dict[str, object]:
    evidence = profile_corruption_evidence(
        _database_profile_identity(engine), engine, reason, profile=profile,
        policy=policy, quarantined=quarantined,
        scan_continued=scan_continued,
    )
    record = evidence.to_json()
    if type(record) is not dict:
        raise ProfileSchemaInvariantError("profile corruption evidence invalid")
    return record


def handle_invalid_engine_profile(
    engine: str, reason: object, *, profile: object = None,
) -> dict[str, object]:
    """Record invalid authority as quarantined/hard-failed and never synthesize replacement truth."""
    if type(engine) is not str or not engine:
        engine = "other"
    policy = get_profile_corruption_policy("hard-fail")
    if policy == "quarantine":
        event = _record_for_policy(
            engine, reason, profile=profile, policy="quarantine",
            quarantined=True, scan_continued=False,
        )
        authoritative_model_state().record_profile_corruption_event(event=event)
        logging.error(
            "PROFILE CORRUPTION QUARANTINED: engine=%s reason=%s",
            engine, event["profile_corruption_reason"],
        )
        raise ProfileSchemaInvariantError(str(event["profile_corruption_reason"]))
    event = _record_for_policy(
        engine, reason, profile=profile, policy="hard-fail",
        quarantined=False, scan_continued=False,
    )
    authoritative_model_state().record_profile_corruption_event(event=event)
    logging.error(
        "PROFILE CORRUPTION DETECTED: engine=%s policy=hard-fail reason=%s",
        engine, event["profile_corruption_reason"],
    )
    raise ProfileSchemaInvariantError(str(event["profile_corruption_reason"]))


__all__ = ("handle_invalid_engine_profile", "profile_corruption_events_snapshot")
