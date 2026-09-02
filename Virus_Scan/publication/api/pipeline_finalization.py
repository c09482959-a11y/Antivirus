"""Publication-owned profile/model finalization API.

Scheduler finalization decides *when* the pipeline is done; publication owns the
side effects that persist profile learning and model state. This module is the
canonical narrow public surface for those side effects so scheduler code no
longer imports model internals directly.
"""

from __future__ import annotations
from typing import TYPE_CHECKING


from Virus_Scan.runtime.api import profile_scoring_state
import Virus_Scan.models.api.profile_persistence as model_profile_persistence_contract
import Virus_Scan.models.api.replay_learning as model_replay_learning_contract
from Virus_Scan.storage import scan_cache_repository

if TYPE_CHECKING:
    from collections.abc import Mapping

def persist_parent_learning_from_results(results: Mapping[str, object]) -> object:
    """Persist parent learning from immutable scheduler results."""
    return model_replay_learning_contract.persist_parent_learning_from_results(results)


def _store_status(name: str, result: object, *, required: bool = True) -> dict[str, object]:
    ok = result is True
    if type(result) is dict:
        explicit_ok = dict.get(result, "ok")
        if type(explicit_ok) is bool:
            ok = explicit_ok
        saved = dict.get(result, "saved")
        degraded = dict.get(result, "degraded")
        if saved is True and degraded is not True:
            ok = True
        if saved is False or degraded is True:
            ok = False
    if not required:
        ok = result is not False
    return {
        "store": name,
        "ok": ok is True,
        "required": required is True,
        "result": result,
    }


def _all_store_statuses_ok(stores: dict[str, object]) -> bool:
    for status in stores.values():
        if type(status) is dict and dict.get(status, "ok") is True:
            continue
        return False
    return True


def flush_all_persistent_models(*, force: bool = True) -> object:
    """Flush candidate custody, model truth, then the disposable cache as separate roles."""
    if type(force) is not bool:
        rejected = _store_status("force_validation", False)
        return {
            "schema_version": "persistent_model_flush_v2",
            "ok": False,
            "stores": {"force_validation": rejected},
        }
    candidate_result = model_profile_persistence_contract.flush_benign_candidate_store(
        force=force
    )
    model_result = model_profile_persistence_contract.flush_authoritative_model_state(
        force=force
    )
    stores = {
        "learning_candidates": _store_status("learning_candidates", candidate_result),
        "model_state": _store_status("model_state", model_result),
    }
    cache_repository = scan_cache_repository()
    scan_cache_required = cache_repository.enabled()
    scan_cache_result = cache_repository.maintenance(force=force)
    stores["scan_cache"] = _store_status(
        "scan_cache", scan_cache_result, required=scan_cache_required,
    )
    return {
        "schema_version": "persistent_model_flush_v2",
        "ok": _all_store_statuses_ok(stores),
        "stores": stores,
    }


def clear_profile_scoring_snapshot() -> None:
    """Clear the runtime-owned profile scoring snapshot at publication finalization.

    Publication owns the finalization timing; runtime/profile_scoring_state owns
    the mutable snapshot.  Keep the boundary direct so publication does not
    reach through model profile internals to clear runtime state.
    """
    profile_scoring_state().clear()


__all__ = (
    "clear_profile_scoring_snapshot",
    "flush_all_persistent_models",
    "persist_parent_learning_from_results",
)
