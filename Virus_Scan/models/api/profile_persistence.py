"""Public canonical model-state persistence contract."""
from __future__ import annotations

from Virus_Scan.runtime.model_state import runtime_model_state_to_json
from Virus_Scan.models.profiles.bootstrap import ensure_authoritative_engine_profiles
from Virus_Scan.models.profiles.persistence import (
    PROFILE_FILE_LOCK,
    flush_profile_writes,
    profile_persistence_state_owner,
    profile_update_marker,
    resolved_profiles_dir,
)
from Virus_Scan.models.profiles.persistence_snapshot import (
    persisted_engine_profile_snapshot,
)
from Virus_Scan.models.profiles.replay_learning import (
    flush_benign_candidate_store,
    get_benign_candidate_store,
)
from Virus_Scan.runtime.environment import runtime_worker_shared_persistence_writes_disabled
from Virus_Scan.runtime.runtime_flags import runtime_flag_clear, runtime_flag_get
from Virus_Scan.storage import authoritative_model_state


def flush_authoritative_model_state(*, force: bool = True) -> dict[str, object]:
    """Commit every dirty authoritative model domain in one SQLite transaction."""
    if type(force) is not bool:
        return {
            "schema_version": "authoritative_model_flush_v2",
            "ok": False,
            "reason": "model_persistence_force_rejected",
        }
    if runtime_worker_shared_persistence_writes_disabled():
        return {
            "schema_version": "authoritative_model_flush_v2",
            "ok": True,
            "worker_deferred": True,
            "transaction_id": "",
        }
    resolved_profiles_dir()
    state = profile_persistence_state_owner()
    with PROFILE_FILE_LOCK:
        dirty = state.dirty_profile_items()
        profiles: list[dict[str, object]] = []
        engines: list[str] = []
        for engine, profile in dirty:
            profile["updated"] = profile_update_marker(profile)
            profiles.append(persisted_engine_profile_snapshot(profile, expected_engine=engine))
            engines.append(engine)
        runtime_dirty = runtime_flag_get("runtime_model_state_dirty")
        runtime_snapshot = runtime_model_state_to_json() if force or runtime_dirty else None
        transaction_id = authoritative_model_state().commit(
            profiles=profiles,
            runtime_snapshot=runtime_snapshot,
            transaction_kind="final_model_flush",
        )
        maintenance = authoritative_model_state().maintain_database()
        state.clear_profile_dirty(engines)
        state.reset_profile_update_count()
        if runtime_snapshot is not None:
            runtime_flag_clear("runtime_model_state_dirty")
        return {
            "schema_version": "authoritative_model_flush_v2",
            "ok": True,
            "transaction_id": transaction_id,
            "profiles_committed": len(profiles),
            "runtime_committed": runtime_snapshot is not None,
            "database_maintenance": maintenance.to_record(),
        }


__all__ = (
    "ensure_authoritative_engine_profiles",
    "flush_authoritative_model_state",
    "flush_benign_candidate_store",
    "flush_profile_writes",
    "get_benign_candidate_store",
)
