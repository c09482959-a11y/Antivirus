"""Canonical staged-benign state through the non-authoritative candidate store owner."""
from __future__ import annotations

from Virus_Scan.runtime.environment import runtime_worker_shared_persistence_writes_disabled
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.models.profiles.common import profile_safe_text
from Virus_Scan.models.profiles.persistence_snapshot import persisted_staged_benign_snapshot
from Virus_Scan.models.profiles.persistence import (
    BENIGN_CANDIDATE_LOCK,
    BENIGN_STAGE_FLUSH_EVERY,
    BULK_DEFER_BENIGN_STAGE_WRITES,
    profile_persistence_state_owner,
    resolved_profiles_dir,
)
from Virus_Scan.models.profiles.staged_store_schema import (
    default_staged_benign_store,
    validate_staged_benign_store,
)
from Virus_Scan.storage import learning_candidate_store


def _new_benign_candidate_store() -> dict[str, object]:
    return default_staged_benign_store()


def benign_candidate_store_failure(stage: object, exc: object) -> object:
    return {
        "saved": False,
        "degraded": True,
        "error": profile_safe_text(stage, replacement="benign_candidate_store_failed"),
        "error_type": no_hook_type_name(exc),
        "final_json_must_record": True,
        "replay_record_required": True,
    }


def flush_benign_candidate_store(*, force: object = False) -> object:
    """Commit staged-benign state through the non-authoritative candidate database."""
    if type(force) is not bool:
        return benign_candidate_store_failure(
            "benign_candidate_store_force_rejected",
            TypeError("force must be bool"),
        )
    if runtime_worker_shared_persistence_writes_disabled():
        return True
    with BENIGN_CANDIDATE_LOCK:
        state = profile_persistence_state_owner()
        store = state.get_staged_cache()
        if store is None or (not force and not state.staged_dirty()):
            return True
        snapshot = persisted_staged_benign_snapshot(store)
        validate_staged_benign_store(snapshot)
        resolved_profiles_dir()
        learning_candidate_store().commit_staged_store(
            snapshot, transaction_kind="staged_store_flush",
        )
        state.set_staged_cache(store, dirty=False)
        state.reset_staged_update_count()
        return True


def get_benign_candidate_store() -> object:
    """Return the cached current-schema staged store."""
    with BENIGN_CANDIDATE_LOCK:
        cached = profile_persistence_state_owner().get_staged_cache()
        if cached is not None:
            return cached
        return load_benign_candidate_store()


def load_benign_candidate_store() -> object:
    """Load staged state from the sole non-authoritative candidate database."""
    with BENIGN_CANDIDATE_LOCK:
        resolved_profiles_dir()
        store = learning_candidate_store().read_staged_store()
        if store is None:
            store = _new_benign_candidate_store()
        validate_staged_benign_store(store)
        return profile_persistence_state_owner().set_staged_cache(store, dirty=False)


def mark_benign_candidate_store_dirty(store: object = None, *, force_flush: object = False) -> object:
    if store is not None and type(store) is not dict:
        return benign_candidate_store_failure(
            "benign_candidate_store_dirty_rejected",
            TypeError("staged store must be an owned dictionary"),
        )
    if type(force_flush) is not bool:
        return benign_candidate_store_failure(
            "benign_candidate_store_force_rejected",
            TypeError("force_flush must be bool"),
        )
    with BENIGN_CANDIDATE_LOCK:
        state = profile_persistence_state_owner()
        update_count = state.mark_staged_dirty(store)
        if force_flush or not BULK_DEFER_BENIGN_STAGE_WRITES or update_count >= BENIGN_STAGE_FLUSH_EVERY:
            return flush_benign_candidate_store(force=force_flush)
        return True


def save_benign_candidate_store(store: object) -> object:
    if type(store) is not dict:
        return benign_candidate_store_failure(
            "benign_candidate_store_save_rejected",
            TypeError("staged store must be an owned dictionary"),
        )
    validate_staged_benign_store(store)
    with BENIGN_CANDIDATE_LOCK:
        profile_persistence_state_owner().set_staged_cache(store, dirty=True)
        return flush_benign_candidate_store(force=True)


__all__ = (
    "benign_candidate_store_failure",
    "flush_benign_candidate_store",
    "get_benign_candidate_store",
    "load_benign_candidate_store",
    "mark_benign_candidate_store_dirty",
    "save_benign_candidate_store",
)
