"""Canonical engine-profile persistence through the authoritative SQLite owner."""
from __future__ import annotations

from pathlib import Path
import sqlite3
from threading import RLock

from Virus_Scan.exception_contracts import (
    IO_CONFIGURATION_ERRORS, RECOVERABLE_RUNTIME_ERRORS,
)
from Virus_Scan.runtime.resource_paths import program_root
from Virus_Scan.runtime.config_state import get_profiles_dir
from Virus_Scan.runtime.profile_persistence_state import profile_persistence_state
from Virus_Scan.runtime.init_state import get_init_value
from Virus_Scan.runtime.environment import runtime_worker_shared_persistence_writes_disabled
from Virus_Scan.models.profiles.common import (
    profile_int,
    profile_mapping_get,
    profile_mapping_items,
    profile_safe_text,
)
from Virus_Scan.models.profiles.schema import (
    ProfileSchemaInvariantError,
    validate_engine_profile_schema,
)
from Virus_Scan.models.profiles.schema_versions import PROFILE_SCHEMA_VERSION
from Virus_Scan.models.profiles.persistence_snapshot import persisted_engine_profile_snapshot
from Virus_Scan.models.profiles.tag_state_projection import materialize_profile_tag_state_projections
from Virus_Scan.models.profiles.quarantine import handle_invalid_engine_profile
from Virus_Scan.storage import authoritative_model_state

_PROFILE_PERSISTENCE_STATE = profile_persistence_state()


def profile_persistence_state_owner() -> object:
    """Return the runtime-owned in-memory profile state."""
    return _PROFILE_PERSISTENCE_STATE


DEFAULT_ENGINES = tuple(
    get_init_value("DEFAULT_ENGINES") or ("renpy", "rpgm", "unity", "media", "other")
)
PROFILES_DIR = get_profiles_dir(None) or str(Path(str(program_root()), "profiles"))
PROFILE_FILE_LOCK = get_init_value("PROFILE_FILE_LOCK") or RLock()
BENIGN_CANDIDATE_LOCK = get_init_value("BENIGN_CANDIDATE_LOCK") or RLock()
BULK_DEFER_PROFILE_WRITES = bool(get_init_value("BULK_DEFER_PROFILE_WRITES"))
BULK_PROFILE_FLUSH_EVERY = int(get_init_value("BULK_PROFILE_FLUSH_EVERY") or 1000000000)
BULK_DEFER_BENIGN_STAGE_WRITES = bool(
    get_init_value("BULK_DEFER_BENIGN_STAGE_WRITES")
    if get_init_value("BULK_DEFER_BENIGN_STAGE_WRITES") is not None
    else True
)
BENIGN_STAGE_FLUSH_EVERY = int(get_init_value("BENIGN_STAGE_FLUSH_EVERY") or 250)
PROFILE_FLUSH_EVERY = int(get_init_value("PROFILE_FLUSH_EVERY") or 25)
PROFILE_PERSISTENCE_FAILURES = RECOVERABLE_RUNTIME_ERRORS + (sqlite3.Error,)


def _profile_engine_key(engine: object) -> str:
    engine_text = profile_safe_text(engine, replacement="other").lower()
    return engine_text if engine_text in DEFAULT_ENGINES else "other"


def _profile_mapping_values(mapping: object) -> object:
    items = profile_mapping_items(mapping)
    return () if items is None else tuple(value for _key, value in items)


def profile_update_marker(profile: object) -> object:
    """Derive deterministic update metadata from learned state."""
    if profile_mapping_items(profile) is None:
        return 0.0
    total = 0.0
    for baseline in _profile_mapping_values(profile_mapping_get(profile, "extension_baselines")):
        if profile_mapping_items(baseline) is None:
            continue
        total += profile_int(profile_mapping_get(baseline, "files"))
        total += profile_int(profile_mapping_get(profile_mapping_get(baseline, "risk"), "samples"))
        total += profile_int(
            profile_mapping_get(profile_mapping_get(baseline, "timeline_baseline"), "sample_count")
        )
        gate = profile_mapping_get(baseline, "learning_gate")
        total += profile_int(profile_mapping_get(gate, "accepted"))
        total += profile_int(profile_mapping_get(gate, "rejected"))
    rejections = profile_mapping_get(profile_mapping_get(profile, "model_state"), "learning_rejections")
    total += sum(profile_int(value) for value in _profile_mapping_values(rejections))
    return total


def profile_ext_lock(engine: object, ext: object) -> object:
    profile_ext_locks = get_init_value("PROFILE_EXT_LOCKS")
    if profile_ext_locks is None:
        return PROFILE_FILE_LOCK
    engine_text = profile_safe_text(engine, replacement="other") or "other"
    ext_text = profile_safe_text(ext, replacement="<no_ext>") or "<no_ext>"
    try:
        return profile_ext_locks[(engine_text, ext_text)]
    except KeyError:
        return PROFILE_FILE_LOCK


def resolved_profiles_dir() -> str:
    """Bind caches and the canonical SQLite lifecycle to one profiles directory."""
    try:
        configured = get_profiles_dir(None)
    except IO_CONFIGURATION_ERRORS:
        configured = None
    configured_text = profile_safe_text(configured, replacement="")
    resolved = (
        configured_text
        if configured_text.lower() not in {"none", "null", ""}
        else str(Path(str(program_root()), "profiles"))
    )
    _PROFILE_PERSISTENCE_STATE.bind_profiles_dir(resolved)
    authoritative_model_state().configure(resolved)
    return resolved


def get_scoring_profile(engine: object) -> object:
    return load_engine_profile(_profile_engine_key(engine))


def flush_profile_writes(*, force: object = False) -> object:
    """Commit all dirty engine profiles in one authoritative SQLite transaction."""
    if type(force) is not bool:
        return False
    if runtime_worker_shared_persistence_writes_disabled():
        return True
    resolved_profiles_dir()
    with PROFILE_FILE_LOCK:
        dirty = _PROFILE_PERSISTENCE_STATE.dirty_profile_items()
        if not dirty:
            return True
        snapshots: list[dict[str, object]] = []
        engines: list[str] = []
        persisted_before = {
            _profile_engine_key(engine): authoritative_model_state().read_profile(
                _profile_engine_key(engine),
            )
            for engine, _profile in dirty
        }
        try:
            for engine, profile in dirty:
                engine_key = _profile_engine_key(engine)
                profile["engine"] = engine_key
                profile["updated"] = profile_update_marker(profile)
                snapshot = persisted_engine_profile_snapshot(profile, expected_engine=engine_key)
                validate_engine_profile_schema(snapshot, expected_engine=engine_key)
                snapshots.append(snapshot)
                engines.append(engine_key)
            authoritative_model_state().commit(
                profiles=snapshots,
                transaction_kind="profile_flush",
            )
        except PROFILE_PERSISTENCE_FAILURES:
            for engine, persisted in persisted_before.items():
                _PROFILE_PERSISTENCE_STATE.restore_engine_profile(engine, persisted)
            _PROFILE_PERSISTENCE_STATE.reset_profile_update_count()
            raise
        for engine, profile in dirty:
            _PROFILE_PERSISTENCE_STATE.cache_engine_profile(_profile_engine_key(engine), profile)
        _PROFILE_PERSISTENCE_STATE.clear_profile_dirty(engines)
        _PROFILE_PERSISTENCE_STATE.reset_profile_update_count()
        return True


def load_engine_profile(engine: object) -> object:
    engine_key = _profile_engine_key(engine)
    with PROFILE_FILE_LOCK:
        resolved_profiles_dir()
        cached = _PROFILE_PERSISTENCE_STATE.get_engine_profile(engine_key)
        if cached is not None:
            return cached
        profile = None
        try:
            profile = authoritative_model_state().read_profile(engine_key)
        except ValueError as exc:
            handle_invalid_engine_profile(engine_key, exc, profile=None)
        if profile is None:
            raise ProfileSchemaInvariantError(
                "authoritative engine profile missing; canonical bootstrap required"
            )
        try:
            validate_engine_profile_schema(profile, expected_engine=engine_key)
        except (ProfileSchemaInvariantError, ValueError) as exc:
            handle_invalid_engine_profile(engine_key, exc, profile=profile)
        materialize_profile_tag_state_projections(profile)
        return _PROFILE_PERSISTENCE_STATE.cache_engine_profile(engine_key, profile)


def save_engine_profile(engine: object, profile: object, *, force: object = False) -> None:
    engine_key = _profile_engine_key(engine)
    if type(force) is not bool:
        raise TypeError("profile force flag must be bool")
    if type(profile) is not dict:
        raise TypeError("engine profile must be an owned dictionary")
    with PROFILE_FILE_LOCK:
        resolved_profiles_dir()
        persisted_before = authoritative_model_state().read_profile(engine_key)
        try:
            profile["engine"] = engine_key
            profile["updated"] = profile_update_marker(profile)
            validate_engine_profile_schema(profile, expected_engine=engine_key)
        except PROFILE_PERSISTENCE_FAILURES:
            _PROFILE_PERSISTENCE_STATE.restore_engine_profile(
                engine_key, persisted_before,
            )
            raise
        update_count = _PROFILE_PERSISTENCE_STATE.mark_profile_dirty(engine_key, profile)
        if runtime_worker_shared_persistence_writes_disabled():
            return
        threshold = (
            BULK_PROFILE_FLUSH_EVERY
            if BULK_DEFER_PROFILE_WRITES and not force
            else PROFILE_FLUSH_EVERY
        )
        if force or update_count >= threshold:
            if flush_profile_writes(force=force) is not True:
                raise OSError("profile SQLite commit failed")


__all__ = (
    "BENIGN_CANDIDATE_LOCK",
    "BENIGN_STAGE_FLUSH_EVERY",
    "BULK_DEFER_BENIGN_STAGE_WRITES",
    "BULK_DEFER_PROFILE_WRITES",
    "BULK_PROFILE_FLUSH_EVERY",
    "DEFAULT_ENGINES",
    "PROFILES_DIR",
    "PROFILE_FILE_LOCK",
    "PROFILE_FLUSH_EVERY",
    "PROFILE_SCHEMA_VERSION",
    "flush_profile_writes",
    "get_scoring_profile",
    "load_engine_profile",
    "profile_ext_lock",
    "profile_persistence_state_owner",
    "profile_update_marker",
    "resolved_profiles_dir",
    "save_engine_profile",
)
