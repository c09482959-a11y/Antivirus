"""Canonical detached staged-benign transition owner for profile learning."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import os

from Virus_Scan.models.contracts.learning_authority import learning_authorization_failure
from Virus_Scan.models.profiles.common import (
    profile_int,
    profile_public_path_text,
    profile_safe_text,
)
from Virus_Scan.models.profiles.persistence_snapshot import persisted_staged_benign_snapshot
from Virus_Scan.models.profiles.promotion_observations import (
    begin_observation,
    update_observation,
)
from Virus_Scan.models.profiles.promotion_policy import promotion_inputs
from Virus_Scan.models.profiles.promotion_state import (
    candidate_should_promote,
    stage_candidate_record,
)
from Virus_Scan.models.profiles.replay_learning import get_benign_candidate_store
from Virus_Scan.models.profiles.staged_store_schema import (
    default_staged_benign_store,
    validate_staged_benign_store,
)
from Virus_Scan.models.profiles.transaction_contracts import LearningCommitRequest
from Virus_Scan.runtime.init_state import get_init_value
from Virus_Scan.runtime.structured_failures import record_suppressed_failure
from Virus_Scan.utils.stages import normalize_profile_extension

PROMOTE_AFTER_CLEAN_OBS = int(get_init_value("PROMOTE_AFTER_CLEAN_OBS") or 3)
MAX_RISK_FOR_PROMOTION = float(get_init_value("MAX_RISK_FOR_PROMOTION") or 20.0)
MIN_PROMOTION_SPREAD_DAYS = float(get_init_value("MIN_PROMOTION_SPREAD_DAYS") or 2.0)


@dataclass(frozen=True, slots=True)
class BenignObservationTransition:
    """One detached current-schema staged-state transition."""

    promoted: bool
    reason: str
    candidate: dict[str, object] | None
    staged_store: dict[str, object]


def _transition(
    store: dict[str, object], promoted: bool, reason: str,
    candidate: dict[str, object] | None,
) -> BenignObservationTransition:
    snapshot = persisted_staged_benign_snapshot(store)
    return BenignObservationTransition(promoted, reason, candidate, snapshot)


def _candidate_reject(
    store: dict[str, object], reason: str,
) -> BenignObservationTransition:
    rejections = store.setdefault("rejections", {})
    if type(rejections) is not dict:
        rejections = {}
        store["rejections"] = rejections
    rejections[reason] = profile_int(rejections.get(reason, 0), 0) + 1
    return _transition(store, False, reason, None)


def _scan_hash_for_staging(file_path: object) -> str:
    h = hashlib.sha256()
    path_text, path_reason = profile_public_path_text(
        file_path, reason="profile_staging_path_invalid", replacement="",
    )
    identity_text = path_text if path_reason is None else path_reason
    h.update(identity_text.encode("utf-8", errors="ignore"))
    if path_reason is None and path_text != "":
        try:
            with open(path_text, "rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    h.update(chunk)
        except OSError as exc:
            record_suppressed_failure(
                "profile_staging_hash_read_failed", exc, domain="model",
            )
    return h.hexdigest()


def _staged_candidate_key(file_path: object, engine: object) -> tuple[str, str, str, str]:
    sha = _scan_hash_for_staging(file_path)
    path_text, _reason = profile_public_path_text(
        file_path, reason="profile_staging_path_invalid", replacement="",
    )
    extension = normalize_profile_extension(path_text)
    engine_text = profile_safe_text(engine, replacement="other") or "other"
    return ":".join((engine_text, extension, sha)), sha, engine_text, path_text


def _replay_result(
    store: dict[str, object], entry: dict[str, object],
) -> BenignObservationTransition:
    candidate_key = entry.get("candidate_key", "")
    candidates = store.get("candidates", {})
    candidate = candidates.get(candidate_key) if type(candidates) is dict else None
    promoted = entry.get("promoted") is True
    reason = entry.get("reason")
    if type(reason) is not str or reason == "":
        reason = (
            "promoted_after_multiple_clean_observations"
            if promoted else "staged_pending_more_clean_observations"
        )
    return _transition(
        store, promoted, reason, candidate if type(candidate) is dict else None,
    )


def _reject_request(
    store: dict[str, object], request: LearningCommitRequest, reason: str,
) -> BenignObservationTransition:
    try:
        update_observation(store, request, status="rejected", reason=reason)
    except ValueError:
        return _candidate_reject(store, "learning_observation_ledger_invalid")
    return _candidate_reject(store, reason)


def prepare_benign_observation(
    request: LearningCommitRequest,
) -> BenignObservationTransition:
    """Prepare one exact observation without mutating or persisting live state."""
    current = get_benign_candidate_store()
    if type(current) is not dict:
        return BenignObservationTransition(
            False, "benign_candidate_store_unavailable", None,
            default_staged_benign_store(),
        )
    try:
        validate_staged_benign_store(current)
    except ValueError:
        return BenignObservationTransition(
            False, "benign_candidate_store_invalid", None,
            default_staged_benign_store(),
        )
    store = deepcopy(current)
    try:
        request.validate()
    except ValueError:
        return _candidate_reject(store, "learning_commit_request_invalid")
    authorization_reason = learning_authorization_failure(request.decision, "profile")
    if authorization_reason is not None:
        return _candidate_reject(store, authorization_reason)
    try:
        action, entry, ledger_reason = begin_observation(store, request)
    except ValueError:
        return _candidate_reject(store, "learning_observation_ledger_invalid")
    if ledger_reason is not None:
        return _candidate_reject(store, ledger_reason)
    assert entry is not None
    if action == "replay" and entry.get("status") != "pending":
        return _replay_result(store, entry)

    tags_l, _yara_hits, ordered_events, risk, policy_reason = promotion_inputs(request)
    if policy_reason is not None:
        return _reject_request(store, request, policy_reason)

    key, sha, engine, path_text = _staged_candidate_key(
        request.file_path, request.engine,
    )
    extension = normalize_profile_extension(path_text)
    candidate, now = stage_candidate_record(
        store, key, sha, engine, os.path.abspath(path_text), extension, risk,
        tags_l, ordered_events, minimum_spread_days=MIN_PROMOTION_SPREAD_DAYS,
        promote_after=PROMOTE_AFTER_CLEAN_OBS,
    )
    promoted = candidate_should_promote(
        candidate, now, promote_after=PROMOTE_AFTER_CLEAN_OBS,
        maximum_risk=MAX_RISK_FOR_PROMOTION,
        minimum_spread_days=MIN_PROMOTION_SPREAD_DAYS,
    )
    reason = "staged_pending_more_clean_observations"
    if promoted:
        candidate["promoted"] = True
        candidate["promoted_at"] = now
        store["promotions"] = profile_int(store.get("promotions", 0), 0) + 1
        reason = "promoted_after_multiple_clean_observations"
    update_observation(
        store, request, status="promoted" if promoted else "staged",
        reason=reason, candidate_key=key, promoted=promoted,
    )
    return _transition(store, promoted, reason, candidate)


__all__ = (
    "BenignObservationTransition",
    "MAX_RISK_FOR_PROMOTION",
    "MIN_PROMOTION_SPREAD_DAYS",
    "PROMOTE_AFTER_CLEAN_OBS",
    "prepare_benign_observation",
)
