"""Canonical relational engine-profile bootstrap owner."""
from __future__ import annotations

from Virus_Scan.models.profiles.persistence import (
    DEFAULT_ENGINES,
    PROFILE_FILE_LOCK,
    load_engine_profile,
    resolved_profiles_dir,
)
from Virus_Scan.models.profiles.persistence_snapshot import (
    persisted_engine_profile_snapshot,
)
from Virus_Scan.models.profiles.schema import validate_engine_profile_schema
from Virus_Scan.models.profiles.snapshots import default_engine_profile
from Virus_Scan.storage import authoritative_model_state


def ensure_authoritative_engine_profiles() -> dict[str, object]:
    """Create every missing default engine profile in one SQLite transaction."""
    resolved_profiles_dir()
    with PROFILE_FILE_LOCK:
        missing: list[dict[str, object]] = []
        created: list[str] = []
        existing: list[str] = []
        for engine in DEFAULT_ENGINES:
            persisted = authoritative_model_state().read_profile(engine)
            if persisted is None:
                profile = default_engine_profile(engine)
                validate_engine_profile_schema(profile, expected_engine=engine)
                missing.append(persisted_engine_profile_snapshot(
                    profile, expected_engine=engine,
                ))
                created.append(engine)
            else:
                existing.append(engine)
        transaction_id = ""
        if missing:
            transaction_id = authoritative_model_state().commit(
                profiles=missing, transaction_kind="profile_bootstrap",
            )
        for engine in DEFAULT_ENGINES:
            load_engine_profile(engine)
        return {
            "schema_version": "authoritative_profile_bootstrap_v1",
            "ok": True,
            "transaction_id": transaction_id,
            "created": tuple(created),
            "existing": tuple(existing),
        }


__all__ = ("ensure_authoritative_engine_profiles",)
