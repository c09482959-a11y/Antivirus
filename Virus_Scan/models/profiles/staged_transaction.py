"""Canonical staged-only non-authoritative candidate transaction boundary."""
from __future__ import annotations

from copy import deepcopy

from Virus_Scan.models.profiles.persistence import (
    profile_persistence_state_owner,
    resolved_profiles_dir,
)
from Virus_Scan.models.profiles.persistence_snapshot import persisted_staged_benign_snapshot
from Virus_Scan.storage import learning_candidate_store


def commit_staged_observation(
    staged_store: dict[str, object], *, replay_key: str,
) -> str:
    """Persist one staged observation and publish its cache only after commit."""
    snapshot = persisted_staged_benign_snapshot(staged_store)
    resolved_profiles_dir()
    transaction_id = learning_candidate_store().commit_staged_store(
        snapshot, transaction_kind="staged_observation", replay_key=replay_key,
    )
    state = profile_persistence_state_owner()
    state.set_staged_cache(deepcopy(snapshot), dirty=False)
    state.reset_staged_update_count()
    return transaction_id


__all__ = ("commit_staged_observation",)
