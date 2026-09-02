from __future__ import annotations

from pathlib import Path
from threading import RLock
import sqlite3

from Virus_Scan.contracts.artifact_read_snapshot import require_artifact_read_snapshot
from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.contracts.scan_cache_fingerprint import ScanCacheExecutionIdentity
from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.core.path_utils import core_path_text
from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS
from Virus_Scan.reporting.result_schema import _scan_cache_clone_result
from Virus_Scan.runtime.cache_state import (
    clear_runtime_caches,
    runtime_cache_by_name,
    runtime_cache_get,
    runtime_cache_set,
)
from Virus_Scan.runtime.graph_state import prune_graph_owned
from Virus_Scan.runtime.structured_failures import safe_exception_message
from Virus_Scan.storage import SQLiteLifecycleError, scan_cache_repository

BULK_DEFER_PROFILE_WRITES = False
CACHE_TTL = 3600
MAX_CACHE_ITEMS_PER_MAP = 20000
CACHE_LOCK = RLock()
GRAPH_RISK_CACHE = runtime_cache_by_name("GRAPH_RISK_CACHE")
RISK_CACHE = runtime_cache_by_name("RISK_CACHE")
MARKOV_CACHE = runtime_cache_by_name("MARKOV_CACHE")
TEMPORAL_CACHE = runtime_cache_by_name("TEMPORAL_CACHE")
GRAPH_PROPAGATION_CACHE = runtime_cache_by_name("GRAPH_PROPAGATION_CACHE")
GRAPH_ATTENTION_CACHE = runtime_cache_by_name("GRAPH_ATTENTION_CACHE")


def _cache_exception_text(prefix: object, exc: object) -> object:
    detail = safe_exception_message(exc)
    error_type = no_hook_type_name(exc)
    if detail and detail != error_type:
        return str.__add__(prefix, str.__add__(error_type, str.__add__(": ", detail)))
    return str.__add__(prefix, error_type)


def bulk_scan_maintenance(index: object, prune_every: object = 1000) -> None:
    if index > 0 and index % prune_every == 0:
        if BULK_DEFER_PROFILE_WRITES:
            try:
                prune_graph_owned(max_nodes=5000, max_edges_per_node=80)
            except IO_CONFIGURATION_ERRORS as exc:
                log_error(_cache_exception_text("bulk graph prune failed: ", exc))
            clear_runtime_caches("GRAPH_RISK_CACHE", "RISK_CACHE", "MARKOV_CACHE")
            return
        prune_graph_owned(max_nodes=5000, max_edges_per_node=80)
        GRAPH_RISK_CACHE.clear()
        RISK_CACHE.clear()
        MARKOV_CACHE.clear()
        maintenance = scan_cache_repository().maintenance(force=True)
        if dict.get(maintenance, "ok") is not True:
            raise OSError("sqlite scan-cache maintenance failed")


def _register_core_runtime_caches() -> None:
    """Validate cache-owner registration without importing shared mutable state."""
    for name in (
        "GRAPH_RISK_CACHE",
        "MARKOV_CACHE",
        "TEMPORAL_CACHE",
        "RISK_CACHE",
        "EVASION_CACHE",
        "GRAPH_PROPAGATION_CACHE",
        "GRAPH_ATTENTION_CACHE",
        "CACHE_STORE",
    ):
        runtime_cache_by_name(name)


def cache_clear_all() -> None:
    """Clear runtime caches through the canonical cache owner."""
    _register_core_runtime_caches()
    clear_runtime_caches()


def cache_get(cache: object, key: object, ttl: object = None) -> object:
    """Return a TTL-aware value from an owned runtime-only cache."""
    ttl = CACHE_TTL if ttl is None else ttl
    with CACHE_LOCK:
        return runtime_cache_get(cache, key, ttl=ttl)


def cache_set(cache: object, key: object, value: object) -> object:
    """Store a value in an owned runtime-only cache."""
    with CACHE_LOCK:
        return runtime_cache_set(cache, key, value, max_items=MAX_CACHE_ITEMS_PER_MAP)


def _umige_passive_asset_cache_hint(artifact_read_snapshot: object) -> bool:
    """Return the passive-asset cache policy from the canonical artifact view."""
    snapshot = require_artifact_read_snapshot(artifact_read_snapshot)
    name = Path(snapshot.canonical_path).name.lower()
    media_exts = {
        ".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif", ".ogg", ".oga",
        ".opus", ".mp3", ".wav", ".flac", ".m4a", ".aac", ".wma", ".mp4",
        ".webm", ".avi", ".mov", ".mkv", ".wmv", ".ttf", ".otf", ".fnt",
        ".woff", ".woff2",
    }
    if any(name.endswith((extension, extension + "_")) for extension in media_exts):
        return True
    return snapshot.read_prefix(16).startswith(
        (b"RPGMV", b"RPGMZ", b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"OggS", b"RIFF", b"ID3")
    )


def pre_scan_cache_lookup(
    artifact_read_snapshot: object,
    *,
    execution_identity: object,
) -> object:
    """Return a validated SQLite cache result from one immutable artifact view."""
    if (
        type(execution_identity) is not ScanCacheExecutionIdentity
        or not execution_identity.cache_eligible
    ):
        return (None, "")
    snapshot = require_artifact_read_snapshot(artifact_read_snapshot)
    if not snapshot.complete:
        return (None, "")
    repository = scan_cache_repository()
    if not repository.enabled():
        return (None, snapshot.content_sha256)
    resolved = snapshot.canonical_path
    cache_unavailable = False
    try:
        fast_key, fast_meta = snapshot.fast_fingerprint()
        if fast_key:
            fast_hit = repository.get_by_fast_fingerprint(
                fast_fingerprint=fast_key,
                fast_fingerprint_payload=fast_meta,
                execution_identity=execution_identity,
                canonical_path=resolved,
                file_name=Path(resolved).name,
                content_size=snapshot.size,
                stat_mtime_ns=snapshot.mtime_ns,
            )
            if fast_hit is not None:
                cloned = _scan_cache_clone_result(
                    fast_hit.result, resolved, fast_hit.content_sha256,
                )
                if type(cloned) is dict:
                    cloned["cache_source"] = "fast_fingerprint"
                    return (cloned, fast_hit.content_sha256)
                return (None, fast_hit.content_sha256)
        sha256 = snapshot.content_sha256
        if _umige_passive_asset_cache_hint(snapshot) and not sha256:
            return (None, fast_key or "")
        hit = repository.get_result(
            content_sha256=sha256,
            execution_identity=execution_identity,
            canonical_path=resolved,
            file_name=Path(resolved).name,
            content_size=snapshot.size,
            fast_fingerprint=fast_key,
            stat_mtime_ns=snapshot.mtime_ns,
        )
        if hit is None:
            return (None, sha256)
        cloned = _scan_cache_clone_result(hit.result, resolved, sha256)
        return (cloned, sha256) if type(cloned) is dict else (None, sha256)
    except (SQLiteLifecycleError, sqlite3.Error) as exc:
        log_error(
            _cache_exception_text(
                str.__add__(
                    "pre-scan SQLite cache unavailable for ",
                    str.__add__(resolved, ": "),
                ),
                exc,
            )
        )
        cache_unavailable = True
    except IO_CONFIGURATION_ERRORS as exc:
        log_error(
            _cache_exception_text(
                str.__add__(
                    "pre-scan cache lookup failed for ",
                    str.__add__(resolved, ": "),
                ),
                exc,
            )
        )
        raise
    if cache_unavailable:
        return (None, snapshot.content_sha256)
    return (None, snapshot.content_sha256)


__all__ = (
    "bulk_scan_maintenance",
    "cache_clear_all",
    "cache_get",
    "cache_set",
    "pre_scan_cache_lookup",
)
