"""Canonical typed owner for the disposable SQLite scan cache."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
from threading import RLock
import time

from Virus_Scan.contracts.static_program_analysis import (
    STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION,
    StaticProgramAnalysis,
)
from Virus_Scan.contracts.scan_cache_fingerprint import (
    SCAN_CACHE_EXECUTION_IDENTITY_VERSION,
    SCAN_CACHE_RESULT_SCHEMA_VERSION,
    ScanCacheExecutionIdentity,
    scan_cache_options_fingerprint,
    scan_cache_options_payload,
)
from Virus_Scan.runtime.api import path_contains_filesystem_alias
from Virus_Scan.storage.sqlite_lifecycle import (
    SQLiteLifecycleError,
    SQLiteLifecycleOwner,
    sqlite_lifecycle,
)

_DEFAULT_MAX_CONTENTS = 20_000
_DEFAULT_MAX_ALIASES_PER_CONTENT = 32
_DEFAULT_MAX_RESULTS_PER_CONTENT = 8
_DEFAULT_MAX_TOTAL_BYTES = 2 * 1024**3
_DEFAULT_MAX_AGE_SECONDS = 30 * 24 * 3600
_HEX = frozenset("0123456789abcdef")
_RUNTIME_ACCOUNTING_TABLE = "scan_cache_runtime_accounting"
_RUNTIME_LRU_TABLE = "scan_cache_runtime_lru"
_RUNTIME_LRU_INDEX = "idx_scan_cache_runtime_lru_last_seen"
_LOGICAL_BYTE_LAYOUT: tuple[tuple[str, tuple[str, ...], int], ...] = (
    ("cache_contents", ("content_sha256",), 16),
    (
        "cache_aliases",
        ("canonical_path", "archive_member", "file_name", "fast_fingerprint"),
        48,
    ),
    (
        "cache_execution_identities",
        ("identity_digest", "schema_version", "payload_json", "payload_sha256"),
        0,
    ),
    (
        "cache_semantic_results",
        (
            "content_sha256",
            "identity_digest",
            "result_schema",
            "result_json",
            "result_sha256",
        ),
        48,
    ),
    (
        "cache_fast_fingerprints",
        ("fast_fingerprint", "content_sha256", "fingerprint_json"),
        16,
    ),
    (
        "cache_parse_results",
        ("content_sha256", "parser_digest", "result_json", "result_sha256", "status"),
        16,
    ),
    (
        "cache_static_operations",
        ("content_sha256", "analysis_digest", "result_json", "result_sha256", "status"),
        16,
    ),
    (
        "cache_scanner_observations",
        (
            "content_sha256",
            "scanner_digest",
            "observations_json",
            "observations_sha256",
            "status",
        ),
        16,
    ),
)

def _exact_text(value: object, reason: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str:
        raise TypeError(reason)
    text = str.__str__(value)
    if not allow_empty and not text:
        raise ValueError(reason)
    return text

def _digest(value: object, reason: str) -> str:
    text = _exact_text(value, reason).lower()
    if len(text) != 64 or any(character not in _HEX for character in text):
        raise ValueError(reason)
    return text


def _nonnegative_int(value: object, reason: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(reason)
    return value


def _positive_int(value: object, reason: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(reason)
    return value


def _json_value(value: object, *, depth: int = 0) -> object:
    """Copy an exact JSON value without invoking user hooks."""
    if depth > 64:
        raise ValueError("scan_cache_json_depth_exceeded")
    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("scan_cache_json_nonfinite")
        return value
    if type(value) in (list, tuple):
        return [_json_value(item, depth=depth + 1) for item in value]
    if type(value) is dict:
        copied: dict[str, object] = {}
        for key, item in dict.items(value):
            if type(key) is not str:
                raise TypeError("scan_cache_json_key_rejected")
            copied[str.__str__(key)] = _json_value(item, depth=depth + 1)
        return copied
    raise TypeError("scan_cache_json_value_rejected")


def _canonical_json(value: object) -> tuple[str, str, object]:
    copied = _json_value(value)
    encoded = json.dumps(
        copied,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return encoded, hashlib.sha256(encoded.encode("utf-8")).hexdigest(), copied


@dataclass(frozen=True, slots=True)
class ScanCacheHit:
    content_sha256: str
    result: dict[str, object]
    source: str


@dataclass(frozen=True, slots=True)
class StaticAnalysisCacheHit:
    content_sha256: str
    analysis_dependency_digest: str
    analysis: StaticProgramAnalysis
    source: str


class ScanCacheRepository:
    """The only production persistence and retention owner for scan-cache rows."""

    def __init__(self, lifecycle: SQLiteLifecycleOwner | None = None) -> None:
        self._lifecycle = sqlite_lifecycle() if lifecycle is None else lifecycle
        self._state_lock = RLock()
        self._enabled = False
        self._read_only = False
        self._runtime_retention_initialized = False

    def configure(self, profiles_dir: object, *, enabled: object) -> None:
        """Configure the parent-owned writable cache authority."""
        if type(enabled) is not bool:
            raise TypeError("scan_cache_enabled_flag_rejected")
        self._lifecycle.configure(profiles_dir)
        connection = None
        if enabled:
            connection = self._lifecycle.connection("cache", query_only=False)
        with self._state_lock:
            self._enabled = enabled
            self._read_only = False
            self._runtime_retention_initialized = False
        if enabled:
            assert connection is not None
            self._rebuild_runtime_retention_state(connection)
            self.configure_retention()
            self.prune_obsolete_rows()

    def configure_reader(self, profiles_dir: object) -> None:
        """Configure one process-local read-only cache reader over an existing database."""
        paths = self._lifecycle.configure(profiles_dir, create=False)
        if (
            path_contains_filesystem_alias(paths.scan_cache)
            or not paths.scan_cache.is_file()
            or paths.scan_cache.stat().st_size <= 0
        ):
            raise SQLiteLifecycleError("scan_cache_reader_database_missing")
        self._lifecycle.connection("cache", query_only=True)
        with self._state_lock:
            self._enabled = True
            self._read_only = True
            self._runtime_retention_initialized = False

    def enabled(self) -> bool:
        with self._state_lock:
            return self._enabled

    def read_only(self) -> bool:
        with self._state_lock:
            return self._enabled and self._read_only

    def writable(self) -> bool:
        with self._state_lock:
            return self._enabled and not self._read_only

    @staticmethod
    def _identity_parts(
        execution_identity: object,
    ) -> tuple[str, str, str, object]:
        if type(execution_identity) is not ScanCacheExecutionIdentity:
            raise TypeError("scan_cache_execution_identity_required")
        if not execution_identity.cache_eligible:
            raise ValueError("scan_cache_execution_identity_ineligible")
        payload = scan_cache_options_payload(execution_identity)
        payload_json, payload_sha, copied = _canonical_json(payload)
        identity_digest = scan_cache_options_fingerprint(execution_identity)
        if payload_sha != identity_digest:
            raise ValueError("scan_cache_identity_digest_mismatch")
        return identity_digest, SCAN_CACHE_EXECUTION_IDENTITY_VERSION, payload_json, copied

    def configure_retention(
        self,
        *,
        max_contents: int = _DEFAULT_MAX_CONTENTS,
        max_aliases_per_content: int = _DEFAULT_MAX_ALIASES_PER_CONTENT,
        max_results_per_content: int = _DEFAULT_MAX_RESULTS_PER_CONTENT,
        max_total_bytes: int = _DEFAULT_MAX_TOTAL_BYTES,
        max_age_seconds: int = _DEFAULT_MAX_AGE_SECONDS,
    ) -> None:
        if not self.writable():
            return
        values = (
            _positive_int(max_contents, "scan_cache_max_contents_invalid"),
            _positive_int(max_aliases_per_content, "scan_cache_max_aliases_invalid"),
            _positive_int(max_results_per_content, "scan_cache_max_results_invalid"),
            _positive_int(max_total_bytes, "scan_cache_max_bytes_invalid"),
            _positive_int(max_age_seconds, "scan_cache_max_age_invalid"),
        )
        with self._lifecycle.transaction("cache") as connection:
            connection.execute(
                "INSERT INTO cache_retention_policy(policy_id,max_contents,max_aliases_per_content,max_results_per_content,"
                "max_total_bytes,max_age_seconds,updated_ns) VALUES(1,?,?,?,?,?,?) "
                "ON CONFLICT(policy_id) DO UPDATE SET max_contents=excluded.max_contents,"
                "max_aliases_per_content=excluded.max_aliases_per_content,"
                "max_results_per_content=excluded.max_results_per_content,"
                "max_total_bytes=excluded.max_total_bytes,max_age_seconds=excluded.max_age_seconds,updated_ns=excluded.updated_ns",
                (*values, time.time_ns()),
            )
            self._enforce_retention(
                connection, now_ns=time.time_ns(), reconcile_all=True,
            )

    @staticmethod
    def _retention_policy(connection: object) -> tuple[int, int, int, int, int]:
        row = connection.execute(
            "SELECT max_contents,max_aliases_per_content,max_results_per_content,max_total_bytes,max_age_seconds "
            "FROM cache_retention_policy WHERE policy_id=1"
        ).fetchone()
        if row is None:
            raise SQLiteLifecycleError("scan_cache_retention_policy_missing")
        return tuple(int(row[index]) for index in range(5))  # type: ignore[return-value]

    @staticmethod
    def _logical_byte_expression(prefix: str, columns: tuple[str, ...], overhead: int) -> str:
        terms = [f"length({prefix}.{column})" for column in columns]
        if overhead:
            terms.append(str(overhead))
        return "+".join(terms)

    @staticmethod
    def _full_logical_bytes(connection: object) -> int:
        row = connection.execute(
            "SELECT "
            "COALESCE((SELECT SUM(length(content_sha256)+16) FROM cache_contents),0)+"
            "COALESCE((SELECT SUM(length(canonical_path)+length(archive_member)+length(file_name)+length(fast_fingerprint)+48) FROM cache_aliases),0)+"
            "COALESCE((SELECT SUM(length(identity_digest)+length(schema_version)+length(payload_json)+length(payload_sha256)) FROM cache_execution_identities),0)+"
            "COALESCE((SELECT SUM(length(content_sha256)+length(identity_digest)+length(result_schema)+length(result_json)+length(result_sha256)+48) FROM cache_semantic_results),0)+"
            "COALESCE((SELECT SUM(length(fast_fingerprint)+length(content_sha256)+length(fingerprint_json)+16) FROM cache_fast_fingerprints),0)+"
            "COALESCE((SELECT SUM(length(content_sha256)+length(parser_digest)+length(result_json)+length(result_sha256)+length(status)+16) FROM cache_parse_results),0)+"
            "COALESCE((SELECT SUM(length(content_sha256)+length(analysis_digest)+length(result_json)+length(result_sha256)+length(status)+16) FROM cache_static_operations),0)+"
            "COALESCE((SELECT SUM(length(content_sha256)+length(scanner_digest)+length(observations_json)+length(observations_sha256)+length(status)+16) FROM cache_scanner_observations),0)"
        ).fetchone()
        return 0 if row is None else int(row[0] or 0)

    def _rebuild_runtime_retention_state(self, connection: object) -> None:
        """Reconcile connection-local O(1)/indexed retention state from persisted cache rows."""
        logical_bytes = self._full_logical_bytes(connection)
        count_row = connection.execute("SELECT COUNT(*) FROM cache_contents").fetchone()
        content_count = 0 if count_row is None else int(count_row[0] or 0)
        connection.execute(
            f"CREATE TEMP TABLE IF NOT EXISTS {_RUNTIME_ACCOUNTING_TABLE}("
            "state_id INTEGER PRIMARY KEY CHECK(state_id=1),"
            "logical_bytes INTEGER NOT NULL CHECK(logical_bytes>=0),"
            "content_count INTEGER NOT NULL CHECK(content_count>=0)) STRICT"
        )
        connection.execute(
            f"CREATE TEMP TABLE IF NOT EXISTS {_RUNTIME_LRU_TABLE}("
            "content_sha256 TEXT PRIMARY KEY NOT NULL,"
            "last_seen_ns INTEGER NOT NULL CHECK(last_seen_ns>=0)) STRICT"
        )
        connection.execute(
            f"CREATE INDEX IF NOT EXISTS temp.{_RUNTIME_LRU_INDEX} "
            f"ON {_RUNTIME_LRU_TABLE}(last_seen_ns,content_sha256)"
        )
        connection.execute(f"DELETE FROM temp.{_RUNTIME_ACCOUNTING_TABLE}")
        connection.execute(
            f"INSERT INTO temp.{_RUNTIME_ACCOUNTING_TABLE}(state_id,logical_bytes,content_count) "
            "VALUES(1,?,?)",
            (logical_bytes, content_count),
        )
        connection.execute(f"DELETE FROM temp.{_RUNTIME_LRU_TABLE}")
        connection.execute(
            f"INSERT INTO temp.{_RUNTIME_LRU_TABLE}(content_sha256,last_seen_ns) "
            "SELECT content_sha256,last_seen_ns FROM cache_contents"
        )
        for table, columns, overhead in _LOGICAL_BYTE_LAYOUT:
            new_cost = self._logical_byte_expression("NEW", columns, overhead)
            old_cost = self._logical_byte_expression("OLD", columns, overhead)
            connection.execute(
                f"CREATE TEMP TRIGGER IF NOT EXISTS scan_cache_runtime_{table}_insert "
                f"AFTER INSERT ON main.{table} BEGIN "
                f"UPDATE {_RUNTIME_ACCOUNTING_TABLE} SET logical_bytes=logical_bytes+({new_cost}) WHERE state_id=1; END"
            )
            connection.execute(
                f"CREATE TEMP TRIGGER IF NOT EXISTS scan_cache_runtime_{table}_update "
                f"AFTER UPDATE ON main.{table} BEGIN "
                f"UPDATE {_RUNTIME_ACCOUNTING_TABLE} SET logical_bytes=logical_bytes-({old_cost})+({new_cost}) WHERE state_id=1; END"
            )
            connection.execute(
                f"CREATE TEMP TRIGGER IF NOT EXISTS scan_cache_runtime_{table}_delete "
                f"AFTER DELETE ON main.{table} BEGIN "
                f"UPDATE {_RUNTIME_ACCOUNTING_TABLE} SET logical_bytes=logical_bytes-({old_cost}) WHERE state_id=1; END"
            )
        connection.execute(
            "CREATE TEMP TRIGGER IF NOT EXISTS scan_cache_runtime_contents_lru_insert "
            "AFTER INSERT ON main.cache_contents BEGIN "
            f"UPDATE {_RUNTIME_ACCOUNTING_TABLE} SET content_count=content_count+1 WHERE state_id=1; "
            f"INSERT INTO {_RUNTIME_LRU_TABLE}(content_sha256,last_seen_ns) VALUES(NEW.content_sha256,NEW.last_seen_ns) "
            "ON CONFLICT(content_sha256) DO UPDATE SET last_seen_ns=excluded.last_seen_ns; END"
        )
        connection.execute(
            "CREATE TEMP TRIGGER IF NOT EXISTS scan_cache_runtime_contents_lru_update "
            "AFTER UPDATE OF content_sha256,last_seen_ns ON main.cache_contents BEGIN "
            f"DELETE FROM {_RUNTIME_LRU_TABLE} WHERE content_sha256=OLD.content_sha256; "
            f"INSERT INTO {_RUNTIME_LRU_TABLE}(content_sha256,last_seen_ns) VALUES(NEW.content_sha256,NEW.last_seen_ns) "
            "ON CONFLICT(content_sha256) DO UPDATE SET last_seen_ns=excluded.last_seen_ns; END"
        )
        connection.execute(
            "CREATE TEMP TRIGGER IF NOT EXISTS scan_cache_runtime_contents_lru_delete "
            "AFTER DELETE ON main.cache_contents BEGIN "
            f"UPDATE {_RUNTIME_ACCOUNTING_TABLE} SET content_count=content_count-1 WHERE state_id=1; "
            f"DELETE FROM {_RUNTIME_LRU_TABLE} WHERE content_sha256=OLD.content_sha256; END"
        )
        with self._state_lock:
            self._runtime_retention_initialized = True

    def _logical_bytes(self, connection: object) -> int:
        with self._state_lock:
            initialized = self._runtime_retention_initialized
        if not initialized:
            return self._full_logical_bytes(connection)
        row = connection.execute(
            f"SELECT logical_bytes FROM temp.{_RUNTIME_ACCOUNTING_TABLE} WHERE state_id=1"
        ).fetchone()
        if row is None:
            raise SQLiteLifecycleError("scan_cache_runtime_accounting_missing")
        value = int(row[0] or 0)
        if value < 0:
            raise SQLiteLifecycleError("scan_cache_runtime_logical_bytes_invalid")
        return value

    def _runtime_content_count(self, connection: object) -> int:
        with self._state_lock:
            if not self._runtime_retention_initialized:
                raise SQLiteLifecycleError("scan_cache_runtime_accounting_uninitialized")
        row = connection.execute(
            f"SELECT content_count FROM temp.{_RUNTIME_ACCOUNTING_TABLE} WHERE state_id=1"
        ).fetchone()
        if row is None:
            raise SQLiteLifecycleError("scan_cache_runtime_accounting_missing")
        value = int(row[0] or 0)
        if value < 0:
            raise SQLiteLifecycleError("scan_cache_runtime_content_count_invalid")
        return value

    @staticmethod
    def _delete_orphan_execution_identity(connection: object, identity_digest: str) -> None:
        connection.execute(
            "DELETE FROM cache_execution_identities WHERE identity_digest=? AND NOT EXISTS ("
            "SELECT 1 FROM cache_semantic_results WHERE identity_digest=?)",
            (identity_digest, identity_digest),
        )

    def _delete_content(self, connection: object, content_sha256: str) -> None:
        identity_digests = tuple(
            str(row[0])
            for row in connection.execute(
                "SELECT identity_digest FROM cache_semantic_results WHERE content_sha256=?",
                (content_sha256,),
            ).fetchall()
        )
        connection.execute("DELETE FROM cache_contents WHERE content_sha256=?", (content_sha256,))
        for identity_digest in identity_digests:
            self._delete_orphan_execution_identity(connection, identity_digest)

    def _prune_content_layers(
        self,
        connection: object,
        *,
        content_sha256: str,
        max_aliases: int,
        max_results: int,
    ) -> None:
        alias_rows = connection.execute(
            "SELECT alias_id FROM cache_aliases WHERE content_sha256=? "
            "ORDER BY last_seen_ns DESC,alias_id DESC",
            (content_sha256,),
        ).fetchall()
        for row in alias_rows[max_aliases:]:
            connection.execute("DELETE FROM cache_aliases WHERE alias_id=?", (int(row[0]),))
        for table, digest_column in (
            ("cache_semantic_results", "identity_digest"),
            ("cache_parse_results", "parser_digest"),
            ("cache_static_operations", "analysis_digest"),
            ("cache_scanner_observations", "scanner_digest"),
        ):
            rows = connection.execute(
                f"SELECT {digest_column} FROM {table} WHERE content_sha256=? "
                f"ORDER BY last_access_ns DESC,{digest_column}",
                (content_sha256,),
            ).fetchall()
            for row in rows[max_results:]:
                digest = str(row[0])
                connection.execute(
                    f"DELETE FROM {table} WHERE content_sha256=? AND {digest_column}=?",
                    (content_sha256, digest),
                )
                if table == "cache_semantic_results":
                    self._delete_orphan_execution_identity(connection, digest)
        connection.execute(
            "DELETE FROM cache_fast_fingerprints WHERE content_sha256=? AND NOT EXISTS ("
            "SELECT 1 FROM cache_aliases WHERE cache_aliases.content_sha256=cache_fast_fingerprints.content_sha256 "
            "AND cache_aliases.fast_fingerprint=cache_fast_fingerprints.fast_fingerprint "
            "AND cache_aliases.fast_fingerprint<>'')",
            (content_sha256,),
        )

    def _enforce_retention(
        self,
        connection: object,
        *,
        now_ns: int,
        touched_content_sha256: str | None = None,
        reconcile_all: bool = False,
    ) -> None:
        max_contents, max_aliases, max_results, max_bytes, max_age = self._retention_policy(connection)
        cutoff = max(0, now_ns - max_age * 1_000_000_000)
        if reconcile_all:
            for row in connection.execute(
                "SELECT content_sha256 FROM cache_contents ORDER BY content_sha256"
            ).fetchall():
                self._prune_content_layers(
                    connection,
                    content_sha256=str(row[0]),
                    max_aliases=max_aliases,
                    max_results=max_results,
                )
            connection.execute(
                "DELETE FROM cache_execution_identities WHERE NOT EXISTS (SELECT 1 FROM cache_semantic_results "
                "WHERE cache_semantic_results.identity_digest=cache_execution_identities.identity_digest)"
            )
        elif touched_content_sha256 is not None:
            self._prune_content_layers(
                connection,
                content_sha256=touched_content_sha256,
                max_aliases=max_aliases,
                max_results=max_results,
            )
        while True:
            oldest = connection.execute(
                f"SELECT content_sha256,last_seen_ns FROM temp.{_RUNTIME_LRU_TABLE} "
                "ORDER BY last_seen_ns ASC,content_sha256 ASC LIMIT 1"
            ).fetchone()
            content_count = self._runtime_content_count(connection)
            logical_bytes = self._logical_bytes(connection)
            must_evict = (
                oldest is not None
                and (
                    int(oldest[1]) < cutoff
                    or content_count > max_contents
                    or logical_bytes > max_bytes
                )
            )
            if not must_evict:
                break
            self._delete_content(connection, str(oldest[0]))

    def prune_obsolete_rows(self) -> None:
        if not self.writable():
            return
        with self._lifecycle.transaction("cache") as connection:
            connection.execute(
                "DELETE FROM cache_semantic_results WHERE result_schema<>? OR identity_digest IN ("
                "SELECT identity_digest FROM cache_execution_identities WHERE schema_version<>?)",
                (SCAN_CACHE_RESULT_SCHEMA_VERSION, SCAN_CACHE_EXECUTION_IDENTITY_VERSION),
            )
            connection.execute(
                "DELETE FROM cache_execution_identities WHERE NOT EXISTS (SELECT 1 FROM cache_semantic_results "
                "WHERE cache_semantic_results.identity_digest=cache_execution_identities.identity_digest)"
            )
            connection.execute(
                "DELETE FROM cache_static_operations WHERE status<>'complete' OR "
                "COALESCE(json_extract(result_json,'$.integrity_status'),'')<>'verified' OR "
                "json_extract(result_json,'$.schema_version') IS NULL OR "
                "json_extract(result_json,'$.schema_version')<>? OR "
                "json_extract(result_json,'$.parser_status') IS NULL OR status<>json_extract(result_json,'$.parser_status')",
                (STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION,),
            )
            self._enforce_retention(
                connection, now_ns=time.time_ns(), reconcile_all=True,
            )

    def put_static_analysis(
        self,
        *,
        content_sha256: object,
        content_size: object,
        analysis_dependency_digest: object,
        analysis: object,
    ) -> bool:
        """Persist one exact recomputable static-analysis result by dependency identity."""
        if not self.writable():
            return False
        sha = _digest(content_sha256, "static_analysis_cache_content_sha256_invalid")
        size = _nonnegative_int(content_size, "static_analysis_cache_content_size_invalid")
        dependency = _digest(
            analysis_dependency_digest,
            "static_analysis_cache_dependency_digest_invalid",
        )
        if type(analysis) is not StaticProgramAnalysis:
            raise TypeError("static_analysis_cache_analysis_required")
        if analysis.content_sha256 != sha or analysis.content_size != size:
            raise ValueError("static_analysis_cache_content_identity_mismatch")
        if analysis.parser_status != "complete" or analysis.integrity_status != "verified":
            with self._lifecycle.transaction("cache") as connection:
                self._delete_invalid_static_analysis(
                    connection, content_sha256=sha, analysis_dependency_digest=dependency,
                )
            return False
        result_json, result_sha, result_copy = _canonical_json(analysis.to_record())
        if type(result_copy) is not dict:
            raise TypeError("static_analysis_cache_record_mapping_required")
        now = time.time_ns()
        with self._lifecycle.transaction("cache") as connection:
            connection.execute(
                "INSERT INTO cache_contents(content_sha256,content_size,first_seen_ns,last_seen_ns) VALUES(?,?,?,?) "
                "ON CONFLICT(content_sha256) DO UPDATE SET content_size=excluded.content_size,last_seen_ns=excluded.last_seen_ns",
                (sha, size, now, now),
            )
            connection.execute(
                "INSERT INTO cache_static_operations(content_sha256,analysis_digest,result_json,result_sha256,status,cached_ns,last_access_ns) "
                "VALUES(?,?,?,?,?,?,?) ON CONFLICT(content_sha256,analysis_digest) DO UPDATE SET "
                "result_json=excluded.result_json,result_sha256=excluded.result_sha256,status=excluded.status," 
                "cached_ns=excluded.cached_ns,last_access_ns=excluded.last_access_ns",
                (sha, dependency, result_json, result_sha, analysis.parser_status, now, now),
            )
            self._enforce_retention(
                connection, now_ns=now, touched_content_sha256=sha,
            )
            retained = connection.execute(
                "SELECT 1 FROM cache_static_operations WHERE content_sha256=? AND analysis_digest=?",
                (sha, dependency),
            ).fetchone()
        return retained is not None

    @staticmethod
    def _delete_invalid_static_analysis(
        connection: object,
        *,
        content_sha256: str,
        analysis_dependency_digest: str,
    ) -> None:
        connection.execute(
            "DELETE FROM cache_static_operations WHERE content_sha256=? AND analysis_digest=?",
            (content_sha256, analysis_dependency_digest),
        )

    def _validated_static_analysis(
        self,
        connection: object,
        *,
        content_sha256: str,
        analysis_dependency_digest: str,
        now_ns: int,
        mutate: bool,
    ) -> StaticAnalysisCacheHit | None:
        row = connection.execute(
            "SELECT result_json,result_sha256,status FROM cache_static_operations "
            "WHERE content_sha256=? AND analysis_digest=?",
            (content_sha256, analysis_dependency_digest),
        ).fetchone()
        if row is None:
            return None
        raw_json = str(row[0])
        expected_sha = str(row[1])
        expected_status = str(row[2])
        valid = hashlib.sha256(raw_json.encode("utf-8")).hexdigest() == expected_sha
        analysis_value: StaticProgramAnalysis | None = None
        if valid:
            try:
                decoded = json.loads(raw_json)
                canonical, digest, copied = _canonical_json(decoded)
                valid = canonical == raw_json and digest == expected_sha and type(copied) is dict
                if valid:
                    analysis_value = StaticProgramAnalysis.from_record(copied)
                    valid = (
                        analysis_value.content_sha256 == content_sha256
                        and expected_status == "complete"
                        and analysis_value.parser_status == expected_status
                        and analysis_value.integrity_status == "verified"
                        and analysis_value.schema_version == STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION
                    )
            except (json.JSONDecodeError, TypeError, ValueError, UnicodeError):
                valid = False
        if not valid or analysis_value is None:
            if mutate:
                self._delete_invalid_static_analysis(
                    connection,
                    content_sha256=content_sha256,
                    analysis_dependency_digest=analysis_dependency_digest,
                )
            return None
        if mutate:
            connection.execute(
                "UPDATE cache_static_operations SET last_access_ns=? WHERE content_sha256=? AND analysis_digest=?",
                (now_ns, content_sha256, analysis_dependency_digest),
            )
            connection.execute(
                "UPDATE cache_contents SET last_seen_ns=? WHERE content_sha256=?",
                (now_ns, content_sha256),
            )
        return StaticAnalysisCacheHit(
            content_sha256=content_sha256,
            analysis_dependency_digest=analysis_dependency_digest,
            analysis=analysis_value,
            source="static_analysis",
        )

    def get_static_analysis(
        self,
        *,
        content_sha256: object,
        analysis_dependency_digest: object,
    ) -> StaticAnalysisCacheHit | None:
        """Return one validated current-schema static-analysis cache row or fail closed."""
        if not self.enabled():
            return None
        sha = _digest(content_sha256, "static_analysis_cache_content_sha256_invalid")
        dependency = _digest(
            analysis_dependency_digest,
            "static_analysis_cache_dependency_digest_invalid",
        )
        now = time.time_ns()
        if self.read_only():
            with self._state_lock:
                return self._validated_static_analysis(
                    self._lifecycle.connection("cache"),
                    content_sha256=sha,
                    analysis_dependency_digest=dependency,
                    now_ns=now,
                    mutate=False,
                )
        with self._lifecycle.transaction("cache") as connection:
            return self._validated_static_analysis(
                connection,
                content_sha256=sha,
                analysis_dependency_digest=dependency,
                now_ns=now,
                mutate=True,
            )

    @staticmethod
    def _upsert_alias(
        connection: object,
        *,
        content_sha256: str,
        canonical_path: str,
        archive_member: str,
        file_name: str,
        fast_fingerprint: str,
        content_size: int,
        stat_mtime_ns: int | None,
        now_ns: int,
    ) -> None:
        connection.execute(
            "INSERT INTO cache_aliases(content_sha256,canonical_path,archive_member,file_name,fast_fingerprint,"
            "stat_size,stat_mtime_ns,first_seen_ns,last_seen_ns) VALUES(?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(content_sha256,canonical_path,archive_member) DO UPDATE SET file_name=excluded.file_name,"
            "fast_fingerprint=excluded.fast_fingerprint,stat_size=excluded.stat_size,"
            "stat_mtime_ns=excluded.stat_mtime_ns,last_seen_ns=excluded.last_seen_ns",
            (
                content_sha256,
                canonical_path,
                archive_member,
                file_name,
                fast_fingerprint,
                content_size,
                stat_mtime_ns,
                now_ns,
                now_ns,
            ),
        )

    def put_result(
        self,
        *,
        content_sha256: object,
        content_size: object,
        canonical_path: object,
        file_name: object,
        execution_identity: object,
        result: object,
        archive_member: object = "",
        fast_fingerprint: object = "",
        fast_fingerprint_payload: object = None,
        stat_mtime_ns: object = None,
    ) -> bool:
        if not self.writable():
            return False
        sha = _digest(content_sha256, "scan_cache_content_sha256_invalid")
        size = _nonnegative_int(content_size, "scan_cache_content_size_invalid")
        path = _exact_text(canonical_path, "scan_cache_canonical_path_invalid")
        name = _exact_text(file_name, "scan_cache_file_name_invalid")
        member = _exact_text(archive_member, "scan_cache_archive_member_invalid", allow_empty=True)
        fast = _exact_text(fast_fingerprint, "scan_cache_fast_fingerprint_invalid", allow_empty=True)
        if fast:
            _digest(fast, "scan_cache_fast_fingerprint_invalid")
            fast_json, _fast_sha, fast_payload = _canonical_json(
                {} if fast_fingerprint_payload is None else fast_fingerprint_payload
            )
        else:
            fast_json, fast_payload = "{}", {}
        mtime = None if stat_mtime_ns is None else _nonnegative_int(
            stat_mtime_ns, "scan_cache_stat_mtime_invalid"
        )
        identity_digest, identity_schema, identity_json, _identity_payload = self._identity_parts(
            execution_identity
        )
        identity_sha = hashlib.sha256(identity_json.encode("utf-8")).hexdigest()
        result_json, result_sha, result_copy = _canonical_json(result)
        if type(result_copy) is not dict:
            raise TypeError("scan_cache_result_mapping_required")
        now = time.time_ns()
        with self._lifecycle.transaction("cache") as connection:
            connection.execute(
                "INSERT INTO cache_contents(content_sha256,content_size,first_seen_ns,last_seen_ns) VALUES(?,?,?,?) "
                "ON CONFLICT(content_sha256) DO UPDATE SET content_size=excluded.content_size,last_seen_ns=excluded.last_seen_ns",
                (sha, size, now, now),
            )
            connection.execute(
                "INSERT INTO cache_execution_identities(identity_digest,schema_version,payload_json,payload_sha256) VALUES(?,?,?,?) "
                "ON CONFLICT(identity_digest) DO UPDATE SET schema_version=excluded.schema_version,"
                "payload_json=excluded.payload_json,payload_sha256=excluded.payload_sha256",
                (identity_digest, identity_schema, identity_json, identity_sha),
            )
            self._upsert_alias(
                connection,
                content_sha256=sha,
                canonical_path=path,
                archive_member=member,
                file_name=name,
                fast_fingerprint=fast,
                content_size=size,
                stat_mtime_ns=mtime,
                now_ns=now,
            )
            if fast:
                connection.execute(
                    "INSERT INTO cache_fast_fingerprints(fast_fingerprint,content_sha256,fingerprint_json,last_seen_ns) "
                    "VALUES(?,?,?,?) ON CONFLICT(fast_fingerprint) DO UPDATE SET "
                    "content_sha256=excluded.content_sha256,fingerprint_json=excluded.fingerprint_json,last_seen_ns=excluded.last_seen_ns",
                    (fast, sha, fast_json, now),
                )
            connection.execute(
                "INSERT INTO cache_semantic_results(content_sha256,identity_digest,result_schema,result_json,result_sha256,"
                "cached_ns,last_access_ns,access_count,integrity_status,partial,truncated) VALUES(?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(content_sha256,identity_digest) DO UPDATE SET result_schema=excluded.result_schema,"
                "result_json=excluded.result_json,result_sha256=excluded.result_sha256,cached_ns=excluded.cached_ns,"
                "last_access_ns=excluded.last_access_ns,access_count=0,integrity_status='verified',partial=0,truncated=0",
                (
                    sha,
                    identity_digest,
                    SCAN_CACHE_RESULT_SCHEMA_VERSION,
                    result_json,
                    result_sha,
                    now,
                    now,
                    0,
                    "verified",
                    0,
                    0,
                ),
            )
            self._enforce_retention(
                connection, now_ns=now, touched_content_sha256=sha,
            )
            retained = connection.execute(
                "SELECT 1 FROM cache_semantic_results WHERE content_sha256=? AND identity_digest=?",
                (sha, identity_digest),
            ).fetchone()
        return retained is not None

    @staticmethod
    def _delete_invalid_result(
        connection: object, *, content_sha256: str, identity_digest: str,
    ) -> None:
        connection.execute(
            "DELETE FROM cache_semantic_results WHERE content_sha256=? AND identity_digest=?",
            (content_sha256, identity_digest),
        )
        connection.execute(
            "DELETE FROM cache_execution_identities WHERE identity_digest=? AND NOT EXISTS ("
            "SELECT 1 FROM cache_semantic_results WHERE identity_digest=?)",
            (identity_digest, identity_digest),
        )

    def _validated_result(
        self,
        connection: object,
        *,
        content_sha256: str,
        execution_identity: object,
        now_ns: int,
        source: str,
        mutate: bool,
    ) -> ScanCacheHit | None:
        identity_digest, identity_schema, identity_json, _identity_payload = self._identity_parts(
            execution_identity
        )
        row = connection.execute(
            "SELECT r.result_schema,r.result_json,r.result_sha256,r.integrity_status,r.partial,r.truncated,"
            "i.schema_version,i.payload_json,i.payload_sha256 "
            "FROM cache_semantic_results AS r JOIN cache_execution_identities AS i "
            "ON i.identity_digest=r.identity_digest WHERE r.content_sha256=? AND r.identity_digest=?",
            (content_sha256, identity_digest),
        ).fetchone()
        if row is None:
            return None
        valid = (
            str(row[0]) == SCAN_CACHE_RESULT_SCHEMA_VERSION
            and str(row[3]) == "verified"
            and int(row[4]) == 0
            and int(row[5]) == 0
            and str(row[6]) == identity_schema
            and str(row[7]) == identity_json
            and str(row[8]) == hashlib.sha256(identity_json.encode("utf-8")).hexdigest()
            and hashlib.sha256(str(row[1]).encode("utf-8")).hexdigest() == str(row[2])
        )
        result: object = None
        if valid:
            try:
                result = json.loads(str(row[1]))
                canonical, digest, copied = _canonical_json(result)
                valid = canonical == str(row[1]) and digest == str(row[2]) and type(copied) is dict
                result = copied
            except (json.JSONDecodeError, TypeError, ValueError, UnicodeError):
                valid = False
        if not valid:
            if mutate:
                self._delete_invalid_result(
                    connection,
                    content_sha256=content_sha256,
                    identity_digest=identity_digest,
                )
            return None
        if mutate:
            connection.execute(
                "UPDATE cache_semantic_results SET last_access_ns=?,access_count=access_count+1 "
                "WHERE content_sha256=? AND identity_digest=?",
                (now_ns, content_sha256, identity_digest),
            )
            connection.execute(
                "UPDATE cache_contents SET last_seen_ns=? WHERE content_sha256=?",
                (now_ns, content_sha256),
            )
        return ScanCacheHit(
            content_sha256=content_sha256,
            result=result,  # type: ignore[arg-type]
            source=source,
        )

    def get_result(
        self,
        *,
        content_sha256: object,
        execution_identity: object,
        canonical_path: object,
        file_name: object,
        content_size: object,
        archive_member: object = "",
        fast_fingerprint: object = "",
        stat_mtime_ns: object = None,
    ) -> ScanCacheHit | None:
        if not self.enabled():
            return None
        sha = _digest(content_sha256, "scan_cache_content_sha256_invalid")
        path = _exact_text(canonical_path, "scan_cache_canonical_path_invalid")
        name = _exact_text(file_name, "scan_cache_file_name_invalid")
        size = _nonnegative_int(content_size, "scan_cache_content_size_invalid")
        member = _exact_text(archive_member, "scan_cache_archive_member_invalid", allow_empty=True)
        fast = _exact_text(fast_fingerprint, "scan_cache_fast_fingerprint_invalid", allow_empty=True)
        if fast:
            _digest(fast, "scan_cache_fast_fingerprint_invalid")
        mtime = None if stat_mtime_ns is None else _nonnegative_int(
            stat_mtime_ns, "scan_cache_stat_mtime_invalid"
        )
        now = time.time_ns()
        if self.read_only():
            with self._state_lock:
                return self._validated_result(
                    self._lifecycle.connection("cache"),
                    content_sha256=sha,
                    execution_identity=execution_identity,
                    now_ns=now,
                    source="sha256",
                    mutate=False,
                )
        with self._lifecycle.transaction("cache") as connection:
            hit = self._validated_result(
                connection,
                content_sha256=sha,
                execution_identity=execution_identity,
                now_ns=now,
                source="sha256",
                mutate=True,
            )
            if hit is not None:
                self._upsert_alias(
                    connection,
                    content_sha256=sha,
                    canonical_path=path,
                    archive_member=member,
                    file_name=name,
                    fast_fingerprint=fast,
                    content_size=size,
                    stat_mtime_ns=mtime,
                    now_ns=now,
                )
                self._enforce_retention(
                    connection, now_ns=now, touched_content_sha256=sha,
                )
        return hit

    def record_result_hit(
        self,
        *,
        content_sha256: object,
        execution_identity: object,
        canonical_path: object,
        file_name: object,
        content_size: object,
        stat_mtime_ns: object = None,
        archive_member: object = "",
    ) -> bool:
        """Parent-record one worker cache hit without republishing semantic data."""
        if not self.writable():
            return False
        sha = _digest(content_sha256, "scan_cache_content_sha256_invalid")
        path = _exact_text(canonical_path, "scan_cache_canonical_path_invalid")
        name = _exact_text(file_name, "scan_cache_file_name_invalid")
        size = _nonnegative_int(content_size, "scan_cache_content_size_invalid")
        member = _exact_text(archive_member, "scan_cache_archive_member_invalid", allow_empty=True)
        mtime = None if stat_mtime_ns is None else _nonnegative_int(
            stat_mtime_ns, "scan_cache_stat_mtime_invalid"
        )
        now = time.time_ns()
        with self._lifecycle.transaction("cache") as connection:
            hit = self._validated_result(
                connection,
                content_sha256=sha,
                execution_identity=execution_identity,
                now_ns=now,
                source="parent_hit_record",
                mutate=True,
            )
            if hit is None:
                return False
            self._upsert_alias(
                connection,
                content_sha256=sha,
                canonical_path=path,
                archive_member=member,
                file_name=name,
                fast_fingerprint="",
                content_size=size,
                stat_mtime_ns=mtime,
                now_ns=now,
            )
            self._enforce_retention(
                connection, now_ns=now, touched_content_sha256=sha,
            )
        return True

    def get_by_fast_fingerprint(
        self,
        *,
        fast_fingerprint: object,
        fast_fingerprint_payload: object,
        execution_identity: object,
        canonical_path: object,
        file_name: object,
        content_size: object,
        stat_mtime_ns: object,
        archive_member: object = "",
    ) -> ScanCacheHit | None:
        if not self.enabled():
            return None
        fast = _digest(fast_fingerprint, "scan_cache_fast_fingerprint_invalid")
        expected_json, _expected_sha, _payload = _canonical_json(fast_fingerprint_payload)
        path = _exact_text(canonical_path, "scan_cache_canonical_path_invalid")
        name = _exact_text(file_name, "scan_cache_file_name_invalid")
        size = _nonnegative_int(content_size, "scan_cache_content_size_invalid")
        mtime = _nonnegative_int(stat_mtime_ns, "scan_cache_stat_mtime_invalid")
        member = _exact_text(archive_member, "scan_cache_archive_member_invalid", allow_empty=True)
        now = time.time_ns()
        if self.read_only():
            with self._state_lock:
                connection = self._lifecycle.connection("cache")
                row = connection.execute(
                    "SELECT content_sha256,fingerprint_json FROM cache_fast_fingerprints WHERE fast_fingerprint=?",
                    (fast,),
                ).fetchone()
                if row is None or str(row[1]) != expected_json:
                    return None
                return self._validated_result(
                    connection,
                    content_sha256=str(row[0]),
                    execution_identity=execution_identity,
                    now_ns=now,
                    source="fast_fingerprint",
                    mutate=False,
                )
        with self._lifecycle.transaction("cache") as connection:
            row = connection.execute(
                "SELECT content_sha256,fingerprint_json FROM cache_fast_fingerprints WHERE fast_fingerprint=?",
                (fast,),
            ).fetchone()
            if row is None:
                return None
            sha = str(row[0])
            if str(row[1]) != expected_json:
                connection.execute(
                    "DELETE FROM cache_fast_fingerprints WHERE fast_fingerprint=?",
                    (fast,),
                )
                return None
            hit = self._validated_result(
                connection,
                content_sha256=sha,
                execution_identity=execution_identity,
                now_ns=now,
                source="fast_fingerprint",
                mutate=True,
            )
            if hit is None:
                return None
            self._upsert_alias(
                connection,
                content_sha256=sha,
                canonical_path=path,
                archive_member=member,
                file_name=name,
                fast_fingerprint=fast,
                content_size=size,
                stat_mtime_ns=mtime,
                now_ns=now,
            )
            connection.execute(
                "UPDATE cache_fast_fingerprints SET last_seen_ns=? WHERE fast_fingerprint=?",
                (now, fast),
            )
            self._enforce_retention(
                connection, now_ns=now, touched_content_sha256=sha,
            )
            return hit

    def clear(self) -> None:
        if not self.writable():
            return
        with self._lifecycle.transaction("cache") as connection:
            connection.execute("DELETE FROM cache_contents")
            connection.execute("DELETE FROM cache_execution_identities")

    def stats(self) -> dict[str, object]:
        if not self.enabled():
            return {
                "schema_version": "sqlite_scan_cache_stats_v2",
                "enabled": False,
                "contents": 0,
                "aliases": 0,
                "results": 0,
                "fast_fingerprints": 0,
                "execution_identities": 0,
                "parse_results": 0,
                "static_analyses": 0,
                "scanner_observations": 0,
                "logical_bytes": 0,
                "database_bytes": 0,
                "wal_bytes": 0,
            }
        connection = self._lifecycle.connection("cache")
        counts = {
            "contents": "cache_contents",
            "aliases": "cache_aliases",
            "results": "cache_semantic_results",
            "fast_fingerprints": "cache_fast_fingerprints",
            "execution_identities": "cache_execution_identities",
            "parse_results": "cache_parse_results",
            "static_analyses": "cache_static_operations",
            "scanner_observations": "cache_scanner_observations",
        }
        output: dict[str, object] = {
            "schema_version": "sqlite_scan_cache_stats_v2",
            "enabled": True,
        }
        for name, table in counts.items():
            row = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
            output[name] = int(row[0] if row else 0)
        output["logical_bytes"] = self._logical_bytes(connection)
        database_path = self._lifecycle.paths().scan_cache
        wal_path = database_path.with_name(database_path.name + "-wal")
        output["database_bytes"] = database_path.stat().st_size
        output["wal_bytes"] = wal_path.stat().st_size if wal_path.is_file() else 0
        output["database_generation"] = self._lifecycle.generation("cache").generation_id
        return output

    def maintenance(self, *, force: object = False) -> dict[str, object]:
        if type(force) is not bool:
            raise TypeError("scan_cache_maintenance_force_rejected")
        if not self.enabled():
            return {
                "schema_version": "sqlite_scan_cache_maintenance_v1",
                "ok": True,
                "enabled": False,
            }
        if self.read_only():
            raise SQLiteLifecycleError("scan_cache_reader_maintenance_rejected")
        with self._lifecycle.transaction("cache") as connection:
            self._rebuild_runtime_retention_state(connection)
            self._enforce_retention(
                connection, now_ns=time.time_ns(), reconcile_all=True,
            )
        integrity = self._lifecycle.integrity_check("cache")
        checkpoint = self._lifecycle.checkpoint(
            "cache", mode="TRUNCATE" if force else "PASSIVE"
        )
        if force:
            self._lifecycle.incremental_vacuum("cache", pages=128)
        return {
            "schema_version": "sqlite_scan_cache_maintenance_v1",
            "ok": integrity.ok is True,
            "enabled": True,
            "integrity": integrity.details,
            "checkpoint": checkpoint,
            "stats": self.stats(),
        }


_SCAN_CACHE_REPOSITORY = ScanCacheRepository()


def scan_cache_repository() -> ScanCacheRepository:
    return _SCAN_CACHE_REPOSITORY


__all__ = (
    "ScanCacheHit",
    "ScanCacheRepository",
    "StaticAnalysisCacheHit",
    "scan_cache_repository",
)
