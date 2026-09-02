"""Single connection, schema, transaction, checkpoint, and integrity owner."""
from __future__ import annotations

from contextlib import contextmanager
import errno
import hashlib
import os
import sqlite3
from pathlib import Path
import shutil
from threading import RLock
import time
from typing import Iterator

from Virus_Scan.storage.contracts import (
    CACHE_DATABASE_APPLICATION_ID,
    CACHE_DATABASE_SCHEMA_VERSION,
    CANDIDATE_DATABASE_APPLICATION_ID,
    CANDIDATE_DATABASE_SCHEMA_VERSION,
    DatabaseBackupArtifact,
    DatabaseGeneration,
    DatabaseIntegrityResult,
    DatabaseKind,
    DatabasePaths,
    MODEL_DATABASE_APPLICATION_ID,
    MODEL_DATABASE_SCHEMA_VERSION,
)
from Virus_Scan.storage.sqlite_schema import (
    CACHE_PRAGMAS,
    CACHE_SCHEMA_DIGEST,
    CACHE_SCHEMA_STATEMENTS,
    CANDIDATE_PRAGMAS,
    CANDIDATE_SCHEMA_DIGEST,
    CANDIDATE_SCHEMA_STATEMENTS,
    MODEL_PRAGMAS,
    MODEL_SCHEMA_DIGEST,
    MODEL_SCHEMA_STATEMENTS,
)
from Virus_Scan.storage.sqlite_wal_integrity import (
    SQLiteWALIntegrityError,
    validate_wal_before_recovery,
)
from Virus_Scan.runtime.resource_lock import ResourceFileLock
from Virus_Scan.runtime.api import (
    durable_replace_regular_file,
    path_contains_filesystem_alias,
)

_BUSY_TIMEOUT_MS = 5000
_AUTO_VACUUM_NONE = 0
_AUTO_VACUUM_FULL = 1
_AUTO_VACUUM_INCREMENTAL = 2
_SYNCHRONOUS_FULL = 2
_AUTO_VACUUM_MIGRATION_CONTRACT = "auto_vacuum_incremental_migration_v1"
_AUTO_VACUUM_MIGRATION_BACKUP_DIRECTORY = ".sqlite_migration_backups"
_KNOWN_GOOD_BACKUP_DIRECTORY = ".sqlite_backups"
_AUTO_VACUUM_MIGRATION_MINIMUM_SAFETY_BYTES = 16 * 1024 * 1024
_MODEL_DATABASE_SEMANTIC_DIGEST = hashlib.sha256(
    b"stage2758_11020_model_semantics_v3_generation_manifest_contract"
).hexdigest()

class SQLiteLifecycleError(RuntimeError):
    """Raised when the canonical SQLite owner cannot establish valid state."""


class SQLiteLifecycleOwner:
    """The only production owner allowed to open persistence SQLite connections."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._paths: DatabasePaths | None = None
        self._model: sqlite3.Connection | None = None
        self._candidate: sqlite3.Connection | None = None
        self._cache: sqlite3.Connection | None = None
        self._generations: dict[DatabaseKind, DatabaseGeneration] = {}
        self._physical_read_only: set[DatabaseKind] = set()
        self._database_process_locks: dict[DatabaseKind, ResourceFileLock] = {}

    def configure(self, profiles_dir: object, *, create: bool = True) -> DatabasePaths:
        if type(create) is not bool:
            raise TypeError("sqlite_configure_create_flag_rejected")
        paths = DatabasePaths.from_profiles_dir(profiles_dir)
        if path_contains_filesystem_alias(paths.profiles_dir):
            raise SQLiteLifecycleError("sqlite_profiles_directory_alias_rejected")
        with self._lock:
            if self._paths == paths:
                return paths
            self.close()
            if create:
                try:
                    paths.profiles_dir.mkdir(parents=True, exist_ok=True)
                except FileExistsError as exc:
                    raise NotADirectoryError(
                        errno.ENOTDIR,
                        "sqlite_profiles_path_not_directory",
                        str(paths.profiles_dir),
                    ) from exc
            elif not paths.profiles_dir.is_dir():
                raise SQLiteLifecycleError("sqlite_profiles_directory_missing")
            self._paths = paths
        return paths

    def paths(self) -> DatabasePaths:
        with self._lock:
            if self._paths is None:
                raise SQLiteLifecycleError("sqlite_lifecycle_not_configured")
            return self._paths

    def _database_spec(self, kind: DatabaseKind) -> tuple[Path, tuple[str, ...], tuple[str, ...], int, int, str]:
        paths = self.paths()
        if kind == "model":
            return (
                paths.model_state, MODEL_SCHEMA_STATEMENTS, MODEL_PRAGMAS,
                MODEL_DATABASE_APPLICATION_ID, MODEL_DATABASE_SCHEMA_VERSION,
                MODEL_SCHEMA_DIGEST,
            )
        if kind == "candidate":
            return (
                paths.learning_candidates, CANDIDATE_SCHEMA_STATEMENTS, CANDIDATE_PRAGMAS,
                CANDIDATE_DATABASE_APPLICATION_ID, CANDIDATE_DATABASE_SCHEMA_VERSION,
                CANDIDATE_SCHEMA_DIGEST,
            )
        if kind == "cache":
            return (
                paths.scan_cache, CACHE_SCHEMA_STATEMENTS, CACHE_PRAGMAS,
                CACHE_DATABASE_APPLICATION_ID, CACHE_DATABASE_SCHEMA_VERSION,
                CACHE_SCHEMA_DIGEST,
            )
        raise ValueError("sqlite_database_kind_invalid")

    @staticmethod
    def _apply_connection_pragmas(connection: sqlite3.Connection, *, initialize: bool) -> None:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        connection.execute(f"PRAGMA synchronous = {_SYNCHRONOUS_FULL}")
        if initialize:
            connection.execute(f"PRAGMA auto_vacuum = {_AUTO_VACUUM_INCREMENTAL}")
            connection.execute("VACUUM")
        mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
        if not mode or str(mode[0]).lower() != "wal":
            raise SQLiteLifecycleError("sqlite_wal_mode_unavailable")
        if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise SQLiteLifecycleError("sqlite_foreign_keys_unavailable")
        if connection.execute("PRAGMA synchronous").fetchone()[0] != _SYNCHRONOUS_FULL:
            raise SQLiteLifecycleError("sqlite_full_synchronous_unavailable")
        if (
            initialize
            and connection.execute("PRAGMA auto_vacuum").fetchone()[0]
            != _AUTO_VACUUM_INCREMENTAL
        ):
            raise SQLiteLifecycleError("sqlite_incremental_auto_vacuum_unavailable")

    @staticmethod
    def _resource_lock_busy(exc: OSError) -> bool:
        error_number = getattr(exc, "errno", None)
        windows_error = getattr(exc, "winerror", None)
        return (
            error_number in {errno.EACCES, errno.EAGAIN, errno.EBUSY}
            or windows_error in {32, 33}
        )

    @classmethod
    def _acquire_resource_lock_bounded(
        cls, lock: ResourceFileLock, *, timeout_reason: str,
    ) -> None:
        deadline = time.monotonic() + (_BUSY_TIMEOUT_MS / 1000)
        while True:
            try:
                lock.acquire()
                return
            except OSError as exc:
                if not cls._resource_lock_busy(exc):
                    raise
                if time.monotonic() >= deadline:
                    raise SQLiteLifecycleError(timeout_reason) from exc
                time.sleep(0.01)

    def _release_database_process_lock(self, kind: DatabaseKind) -> None:
        lock = self._database_process_locks.pop(kind, None)
        if lock is not None:
            lock.release()

    def _acquire_writable_lifecycle_presence(
        self, kind: DatabaseKind, database_path: Path,
    ) -> None:
        """Join one writable database lifecycle and validate only quiescent WALs.

        Every writable lifecycle owner holds a shared presence lock for as long
        as its SQLite connection is live. New owners serialize startup through a
        separate mutex. While holding that mutex, a process may acquire the
        presence lock exclusively only when no other writable lifecycle owner is
        active. Raw WAL validation is permitted only in that exclusive state.
        Otherwise the new owner joins the shared live set and lets SQLite alone
        interpret the mutating WAL.
        """
        if kind in self._database_process_locks:
            return
        presence_path = database_path.with_name(
            database_path.name + ".lifecycle-presence.lock"
        )
        startup_path = database_path.with_name(
            database_path.name + ".lifecycle-startup.lock"
        )
        startup_lock = ResourceFileLock(path=startup_path, writable=True)
        self._acquire_resource_lock_bounded(
            startup_lock, timeout_reason="sqlite_lifecycle_startup_lock_timeout:" + kind,
        )
        shared_lock: ResourceFileLock | None = None
        try:
            exclusive_presence = ResourceFileLock(path=presence_path, writable=True)
            quiescent = False
            try:
                exclusive_presence.acquire()
                quiescent = True
            except OSError as exc:
                if not self._resource_lock_busy(exc):
                    raise
            if quiescent:
                try:
                    validate_wal_before_recovery(database_path)
                finally:
                    exclusive_presence.release()
            shared_lock = ResourceFileLock(path=presence_path, writable=False)
            self._acquire_resource_lock_bounded(
                shared_lock, timeout_reason="sqlite_lifecycle_presence_lock_timeout:" + kind,
            )
            self._database_process_locks[kind] = shared_lock
            shared_lock = None
        finally:
            if shared_lock is not None:
                shared_lock.release()
            startup_lock.release()

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _foreign_key_check_clean(connection: sqlite3.Connection) -> bool:
        return connection.execute("PRAGMA foreign_key_check").fetchone() is None

    @staticmethod
    def _integrity_check_ok(connection: sqlite3.Connection) -> bool:
        rows = connection.execute("PRAGMA integrity_check").fetchall()
        return bool(rows) and all(str(row[0]).lower() == "ok" for row in rows)

    @classmethod
    def _validate_sqlite_backup_identity(
        cls,
        connection: sqlite3.Connection,
        *,
        kind: DatabaseKind,
        source_identity: dict[str, object],
    ) -> None:
        if not cls._integrity_check_ok(connection):
            raise SQLiteLifecycleError("sqlite_auto_vacuum_backup_integrity_failed")
        if not cls._foreign_key_check_clean(connection):
            raise SQLiteLifecycleError("sqlite_auto_vacuum_backup_foreign_key_failed")
        actual_application = int(connection.execute("PRAGMA application_id").fetchone()[0])
        actual_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        actual_digest = cls._database_metadata_value(connection, "schema_digest")
        actual_generation = cls._database_metadata_value(connection, "current_generation_id")
        if (
            actual_application != int(source_identity["application_id"])
            or actual_version != int(source_identity["schema_version"])
            or actual_digest != str(source_identity["schema_digest"])
            or actual_generation != str(source_identity["generation_id"])
        ):
            raise SQLiteLifecycleError("sqlite_auto_vacuum_backup_identity_mismatch")
        if kind == "model":
            rows = connection.execute(
                "SELECT generation_id,schema_digest,semantic_digest,status "
                "FROM database_generations WHERE status='active'"
            ).fetchall()
            if len(rows) != 1:
                raise SQLiteLifecycleError("sqlite_auto_vacuum_backup_generation_invalid")
            row = rows[0]
            if (
                str(row[0]).lower() != str(source_identity["generation_id"])
                or str(row[1]) != str(source_identity["schema_digest"])
                or str(row[2]) != str(source_identity["semantic_digest"])
                or str(row[3]) != "active"
            ):
                raise SQLiteLifecycleError("sqlite_auto_vacuum_backup_semantic_mismatch")

    @classmethod
    def _validated_sqlite_backup(
        cls,
        connection: sqlite3.Connection,
        *,
        path: Path,
        kind: DatabaseKind,
        source_identity: dict[str, object],
    ) -> tuple[Path, str]:
        backup_root = path.parent / _AUTO_VACUUM_MIGRATION_BACKUP_DIRECTORY
        backup_root.mkdir(parents=True, exist_ok=True)
        backup_name = (
            f"{path.name}.{kind}.schema{source_identity['schema_version']}."
            f"generation-{source_identity['generation_id']}.pre-auto-vacuum.sqlite3"
        )
        backup_path = backup_root / backup_name

        if backup_path.exists():
            backup_connection = sqlite3.connect(backup_path, isolation_level=None)
            try:
                cls._validate_sqlite_backup_identity(
                    backup_connection, kind=kind, source_identity=source_identity,
                )
            finally:
                backup_connection.close()
            return backup_path, cls._sha256_file(backup_path)

        temporary_path = backup_root / (
            backup_name + f".tmp-{os.getpid()}-{time.time_ns()}"
        )
        backup_connection = sqlite3.connect(temporary_path, isolation_level=None)
        try:
            connection.backup(backup_connection)
            cls._validate_sqlite_backup_identity(
                backup_connection, kind=kind, source_identity=source_identity,
            )
        except (OSError, sqlite3.Error, SQLiteLifecycleError):
            backup_connection.close()
            temporary_path.unlink(missing_ok=True)
            raise
        else:
            backup_connection.close()

        durable_replace_regular_file(temporary_path, backup_path)
        return backup_path, cls._sha256_file(backup_path)

    @classmethod
    def _supported_existing_identity_snapshot(
        cls,
        connection: sqlite3.Connection,
        *,
        kind: DatabaseKind,
        application_id: int,
        schema_version: int,
        schema_digest: str,
    ) -> dict[str, object]:
        actual_application = int(connection.execute("PRAGMA application_id").fetchone()[0])
        actual_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        actual_digest = cls._database_metadata_value(connection, "schema_digest")

        if actual_application != application_id:
            raise SQLiteLifecycleError("sqlite_database_identity_mismatch")

        if actual_version != schema_version:
            raise SQLiteLifecycleError("sqlite_database_identity_mismatch")
        if actual_digest != schema_digest:
            raise SQLiteLifecycleError("sqlite_schema_digest_mismatch")
        expected_semantic = _MODEL_DATABASE_SEMANTIC_DIGEST if kind == "model" else ""

        generation_id = cls._database_metadata_value(connection, "current_generation_id")
        if generation_id is None:
            raise SQLiteLifecycleError("sqlite_generation_metadata_missing")
        if (
            len(generation_id) != 64
            or any(ch not in "0123456789abcdef" for ch in generation_id.lower())
        ):
            raise SQLiteLifecycleError("sqlite_generation_identity_invalid")
        generation_id = generation_id.lower()

        semantic_digest = ""
        if kind == "model":
            rows = connection.execute(
                "SELECT generation_id,schema_digest,semantic_digest,status "
                "FROM database_generations WHERE status='active'"
            ).fetchall()
            if len(rows) != 1 or str(rows[0][0]).lower() != generation_id:
                raise SQLiteLifecycleError("sqlite_active_generation_invalid")
            semantic_digest = str(rows[0][2])
            if (
                str(rows[0][1]) != actual_digest
                or semantic_digest != expected_semantic
                or str(rows[0][3]) != "active"
            ):
                raise SQLiteLifecycleError("sqlite_active_generation_mismatch")

        return {
            "application_id": actual_application,
            "schema_version": actual_version,
            "schema_digest": actual_digest,
            "generation_id": generation_id,
            "semantic_digest": semantic_digest,
            "identity_class": "current",
        }

    @classmethod
    def _write_auto_vacuum_migration_metadata(
        cls,
        connection: sqlite3.Connection,
        *,
        migration_state: str,
        source_mode: int,
        source_identity: dict[str, object],
        backup_path: Path | None,
        backup_sha256: str,
    ) -> None:
        if migration_state not in {"prepared", "complete"}:
            raise SQLiteLifecycleError("sqlite_auto_vacuum_migration_state_invalid")
        now_ns = time.time_ns()
        records = {
            "auto_vacuum_migration_contract": _AUTO_VACUUM_MIGRATION_CONTRACT,
            "auto_vacuum_migration_state": migration_state,
            "auto_vacuum_migration_source_mode": str(source_mode),
            "auto_vacuum_migration_source_application_id": str(source_identity["application_id"]),
            "auto_vacuum_migration_source_schema_version": str(source_identity["schema_version"]),
            "auto_vacuum_migration_source_schema_digest": str(source_identity["schema_digest"]),
            "auto_vacuum_migration_source_generation_id": str(source_identity["generation_id"]),
            "auto_vacuum_migration_source_semantic_digest": str(source_identity["semantic_digest"]),
            "auto_vacuum_migration_backup_file": "" if backup_path is None else backup_path.name,
            "auto_vacuum_migration_backup_sha256": backup_sha256,
        }
        if migration_state == "complete":
            records["auto_vacuum_migration_completed_ns"] = str(now_ns)
        connection.execute("BEGIN IMMEDIATE")
        committed = False
        try:
            for key, value in records.items():
                connection.execute(
                    "INSERT INTO database_metadata(key,value,updated_ns) VALUES(?,?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_ns=excluded.updated_ns",
                    (key, value, now_ns),
                )
            connection.execute("COMMIT")
            committed = True
        finally:
            if not committed and connection.in_transaction:
                connection.execute("ROLLBACK")

    @classmethod
    def _validate_pending_auto_vacuum_recovery(
        cls,
        connection: sqlite3.Connection,
        *,
        path: Path,
        kind: DatabaseKind,
        source_identity: dict[str, object],
    ) -> None:
        backup_file = cls._database_metadata_value(
            connection, "auto_vacuum_migration_backup_file",
        )
        backup_sha256 = cls._database_metadata_value(
            connection, "auto_vacuum_migration_backup_sha256",
        )
        source_mode = cls._database_metadata_value(
            connection, "auto_vacuum_migration_source_mode",
        )
        if source_mode == str(_AUTO_VACUUM_NONE):
            if not backup_file or not backup_sha256:
                raise SQLiteLifecycleError("sqlite_auto_vacuum_migration_recovery_backup_missing")
            backup_path = path.parent / _AUTO_VACUUM_MIGRATION_BACKUP_DIRECTORY / backup_file
            if not backup_path.is_file() or cls._sha256_file(backup_path) != backup_sha256:
                raise SQLiteLifecycleError("sqlite_auto_vacuum_migration_recovery_backup_invalid")
            backup_connection = sqlite3.connect(backup_path, isolation_level=None)
            try:
                cls._validate_sqlite_backup_identity(
                    backup_connection, kind=kind, source_identity=source_identity,
                )
            finally:
                backup_connection.close()
        if not cls._integrity_check_ok(connection) or not cls._foreign_key_check_clean(connection):
            raise SQLiteLifecycleError("sqlite_auto_vacuum_migration_recovery_database_invalid")
        raise SQLiteLifecycleError("sqlite_auto_vacuum_migration_recovery_required")

    @classmethod
    def _migrate_existing_auto_vacuum(
        cls,
        connection: sqlite3.Connection,
        *,
        path: Path,
        kind: DatabaseKind,
        source_identity: dict[str, object],
    ) -> None:
        source_mode = int(connection.execute("PRAGMA auto_vacuum").fetchone()[0])
        migration_contract = cls._database_metadata_value(
            connection, "auto_vacuum_migration_contract",
        )
        migration_state = cls._database_metadata_value(
            connection, "auto_vacuum_migration_state",
        )
        if migration_state == "prepared":
            cls._validate_pending_auto_vacuum_recovery(
                connection, path=path, kind=kind, source_identity=source_identity,
            )
        if source_mode == _AUTO_VACUUM_INCREMENTAL:
            if migration_contract is None and migration_state is None:
                return
            if (
                migration_contract == _AUTO_VACUUM_MIGRATION_CONTRACT
                and migration_state == "complete"
            ):
                return
            raise SQLiteLifecycleError("sqlite_auto_vacuum_migration_state_inconsistent")
        if source_mode not in {_AUTO_VACUUM_NONE, _AUTO_VACUUM_FULL}:
            raise SQLiteLifecycleError("sqlite_auto_vacuum_mode_invalid")
        if migration_contract is not None or migration_state is not None:
            raise SQLiteLifecycleError("sqlite_auto_vacuum_migration_state_inconsistent")

        checkpoint = connection.execute("PRAGMA wal_checkpoint(FULL)").fetchone()
        if checkpoint is None or int(checkpoint[0]) != 0:
            raise SQLiteLifecycleError("sqlite_auto_vacuum_checkpoint_unavailable")

        backup_path: Path | None = None
        backup_sha256 = ""
        if source_mode == _AUTO_VACUUM_NONE:
            backup_path, backup_sha256 = cls._validated_sqlite_backup(
                connection,
                path=path,
                kind=kind,
                source_identity=source_identity,
            )
            database_bytes = path.stat().st_size
            required_free = (
                (database_bytes * 2)
                + max(_AUTO_VACUUM_MIGRATION_MINIMUM_SAFETY_BYTES, database_bytes // 10)
            )
            if shutil.disk_usage(path.parent).free < required_free:
                raise SQLiteLifecycleError("sqlite_auto_vacuum_migration_free_space_insufficient")

        cls._write_auto_vacuum_migration_metadata(
            connection,
            migration_state="prepared",
            source_mode=source_mode,
            source_identity=source_identity,
            backup_path=backup_path,
            backup_sha256=backup_sha256,
        )
        connection.execute("PRAGMA auto_vacuum = INCREMENTAL")
        if source_mode == _AUTO_VACUUM_NONE:
            connection.execute("VACUUM")

        if int(connection.execute("PRAGMA auto_vacuum").fetchone()[0]) != _AUTO_VACUUM_INCREMENTAL:
            raise SQLiteLifecycleError("sqlite_incremental_auto_vacuum_unavailable")
        if not cls._integrity_check_ok(connection):
            raise SQLiteLifecycleError("sqlite_auto_vacuum_post_migration_integrity_failed")
        if not cls._foreign_key_check_clean(connection):
            raise SQLiteLifecycleError("sqlite_auto_vacuum_post_migration_foreign_key_failed")
        cls._write_auto_vacuum_migration_metadata(
            connection,
            migration_state="complete",
            source_mode=source_mode,
            source_identity=source_identity,
            backup_path=backup_path,
            backup_sha256=backup_sha256,
        )


    @staticmethod
    def _validate_existing_identity(
        connection: sqlite3.Connection, *, application_id: int,
        schema_version: int, schema_digest: str,
    ) -> None:
        actual_application = int(connection.execute("PRAGMA application_id").fetchone()[0])
        actual_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if actual_application != application_id or actual_version != schema_version:
            raise SQLiteLifecycleError("sqlite_database_identity_mismatch")
        metadata_table = connection.execute(
            "SELECT 1 FROM sqlite_schema WHERE type='table' AND name='database_metadata'"
        ).fetchone()
        if metadata_table is None:
            raise SQLiteLifecycleError("sqlite_schema_metadata_missing")
        row = connection.execute(
            "SELECT value FROM database_metadata WHERE key='schema_digest'"
        ).fetchone()
        if row is None or str(row[0]) != schema_digest:
            raise SQLiteLifecycleError("sqlite_schema_digest_mismatch")

    @staticmethod
    def _database_metadata_value(connection: sqlite3.Connection, key: str) -> str | None:
        table = connection.execute(
            "SELECT 1 FROM sqlite_schema WHERE type='table' AND name='database_metadata'"
        ).fetchone()
        if table is None:
            return None
        row = connection.execute(
            "SELECT value FROM database_metadata WHERE key=?", (key,),
        ).fetchone()
        return None if row is None else str(row[0])

    def _open_existing_read_only(self, kind: DatabaseKind) -> sqlite3.Connection:
        path, _statements, _pragma_statements, app_id, user_version, digest = self._database_spec(kind)
        if (
            path_contains_filesystem_alias(path)
            or not path.is_file()
            or path.stat().st_size <= 0
        ):
            raise SQLiteLifecycleError("sqlite_read_only_database_missing")
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                path.as_uri() + "?mode=ro",
                uri=True,
                timeout=_BUSY_TIMEOUT_MS / 1000,
                isolation_level=None,
                check_same_thread=False,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only = ON")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
            connection.execute(f"PRAGMA synchronous = {_SYNCHRONOUS_FULL}")
            if int(connection.execute("PRAGMA query_only").fetchone()[0]) != 1:
                raise SQLiteLifecycleError("sqlite_query_only_mode_unavailable:" + kind)
            if int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
                raise SQLiteLifecycleError("sqlite_foreign_keys_unavailable")
            if int(connection.execute("PRAGMA synchronous").fetchone()[0]) != _SYNCHRONOUS_FULL:
                raise SQLiteLifecycleError("sqlite_full_synchronous_unavailable")
            journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
            if journal_mode != "wal":
                raise SQLiteLifecycleError("sqlite_read_only_journal_mode_invalid")
            auto_vacuum = int(connection.execute("PRAGMA auto_vacuum").fetchone()[0])
            if auto_vacuum != _AUTO_VACUUM_INCREMENTAL:
                raise SQLiteLifecycleError("sqlite_read_only_auto_vacuum_migration_required")
            source_identity = self._supported_existing_identity_snapshot(
                connection,
                kind=kind,
                application_id=app_id,
                schema_version=user_version,
                schema_digest=digest,
            )
            generation = DatabaseGeneration(
                kind=kind,
                path=str(path),
                schema_version=user_version,
                schema_digest=digest,
                generation_id=str(source_identity["generation_id"]),
                journal_mode=journal_mode,
                synchronous=int(connection.execute("PRAGMA synchronous").fetchone()[0]),
                foreign_keys=bool(connection.execute("PRAGMA foreign_keys").fetchone()[0]),
                auto_vacuum=auto_vacuum,
                busy_timeout_ms=int(connection.execute("PRAGMA busy_timeout").fetchone()[0]),
            )
        except (OSError, sqlite3.Error, SQLiteLifecycleError) as exc:
            if connection is not None:
                connection.close()
            if isinstance(exc, SQLiteLifecycleError):
                raise
            raise SQLiteLifecycleError(f"sqlite_read_only_open_failed:{kind}:{exc}") from exc
        if kind == "model":
            self._model = connection
        elif kind == "candidate":
            self._candidate = connection
        else:
            self._cache = connection
        self._generations[kind] = generation
        self._physical_read_only.add(kind)
        return connection

    def _open(
        self, kind: DatabaseKind, *, initial_read_only: bool = False,
    ) -> sqlite3.Connection:
        with self._lock:
            current = (
                self._model if kind == "model" else
                self._candidate if kind == "candidate" else
                self._cache
            )
            if current is not None:
                return current
            if initial_read_only:
                return self._open_existing_read_only(kind)
            path, statements, pragma_statements, app_id, user_version, digest = self._database_spec(kind)
            existed = path.exists() and path.stat().st_size > 0
            try:
                self._acquire_writable_lifecycle_presence(kind, path)
                connection = sqlite3.connect(
                    path, timeout=_BUSY_TIMEOUT_MS / 1000,
                    isolation_level=None, check_same_thread=False,
                )
                connection.row_factory = sqlite3.Row
                self._apply_connection_pragmas(connection, initialize=not existed)
                if existed:
                    source_identity = self._supported_existing_identity_snapshot(
                        connection,
                        kind=kind,
                        application_id=app_id,
                        schema_version=user_version,
                        schema_digest=digest,
                    )
                    self._migrate_existing_auto_vacuum(
                        connection,
                        path=path,
                        kind=kind,
                        source_identity=source_identity,
                    )
                if existed:
                    self._validate_existing_identity(
                        connection, application_id=app_id,
                        schema_version=user_version, schema_digest=digest,
                    )
                else:
                    for statement in pragma_statements:
                        connection.execute(statement)
                    for statement in statements:
                        connection.execute(statement)
                actual_app = int(connection.execute("PRAGMA application_id").fetchone()[0])
                actual_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                if actual_app != app_id or actual_version != user_version:
                    raise SQLiteLifecycleError("sqlite_database_identity_mismatch")
                if existed:
                    generation_row = connection.execute(
                        "SELECT value FROM database_metadata WHERE key='current_generation_id'"
                    ).fetchone()
                    if generation_row is None:
                        raise SQLiteLifecycleError("sqlite_generation_metadata_missing")
                    generation_id = str(generation_row[0]).lower()
                    if (
                        len(generation_id) != 64
                        or any(ch not in "0123456789abcdef" for ch in generation_id)
                    ):
                        raise SQLiteLifecycleError("sqlite_generation_identity_invalid")
                    if kind == "model":
                        rows = connection.execute(
                            "SELECT generation_id,schema_digest,semantic_digest,status "
                            "FROM database_generations WHERE status='active'"
                        ).fetchall()
                        if len(rows) != 1:
                            raise SQLiteLifecycleError("sqlite_active_generation_invalid")
                        active = rows[0]
                        if (
                            str(active[0]) != generation_id
                            or str(active[1]) != digest
                            or str(active[2]) != _MODEL_DATABASE_SEMANTIC_DIGEST
                            or str(active[3]) != "active"
                        ):
                            raise SQLiteLifecycleError("sqlite_active_generation_mismatch")
                else:
                    now_ns = time.time_ns()
                    generation_id = hashlib.sha256(
                        f"{kind}:{path}:{digest}:{now_ns}".encode("utf-8")
                    ).hexdigest()
                    connection.execute("BEGIN IMMEDIATE")
                    metadata_committed = False
                    try:
                        connection.execute(
                            "INSERT INTO database_metadata(key,value,updated_ns) VALUES(?,?,?)",
                            ("schema_digest", digest, now_ns),
                        )
                        connection.execute(
                            "INSERT INTO database_metadata(key,value,updated_ns) VALUES(?,?,?)",
                            ("schema_version", str(user_version), now_ns),
                        )
                        if kind == "model":
                            connection.execute(
                                "INSERT INTO database_generations("
                                "generation_id,schema_digest,semantic_digest,created_ns,status"
                                ") VALUES(?,?,?,?,?)",
                                (
                                    generation_id, digest,
                                    _MODEL_DATABASE_SEMANTIC_DIGEST, now_ns, "active",
                                ),
                            )
                        connection.execute(
                            "INSERT INTO database_metadata(key,value,updated_ns) VALUES(?,?,?)",
                            ("current_generation_id", generation_id, now_ns),
                        )
                        connection.execute("COMMIT")
                        metadata_committed = True
                    finally:
                        if not metadata_committed and connection.in_transaction:
                            connection.execute("ROLLBACK")
                generation = DatabaseGeneration(
                    kind=kind, path=str(path), schema_version=user_version,
                    schema_digest=digest, generation_id=generation_id,
                    journal_mode=str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower(),
                    synchronous=int(connection.execute("PRAGMA synchronous").fetchone()[0]),
                    foreign_keys=bool(connection.execute("PRAGMA foreign_keys").fetchone()[0]),
                    auto_vacuum=int(connection.execute("PRAGMA auto_vacuum").fetchone()[0]),
                    busy_timeout_ms=int(connection.execute("PRAGMA busy_timeout").fetchone()[0]),
                )
            except (OSError, sqlite3.Error, SQLiteLifecycleError, SQLiteWALIntegrityError) as exc:
                if "connection" in locals():
                    connection.close()
                self._release_database_process_lock(kind)
                raise SQLiteLifecycleError(f"sqlite_open_failed:{kind}:{exc}") from exc
            if kind == "model":
                self._model = connection
            elif kind == "candidate":
                self._candidate = connection
            else:
                self._cache = connection
            self._generations[kind] = generation
            return connection

    def connection(
        self, kind: DatabaseKind, *, query_only: bool | None = None,
    ) -> sqlite3.Connection:
        """Return the canonical connection with lifecycle-owned access mode.

        ``query_only`` is a process-local connection policy, not repository
        state.  Callers may request read-only or read-write access, but only
        the lifecycle owner mutates and verifies the SQLite PRAGMA.
        """
        if query_only is not None and type(query_only) is not bool:
            raise TypeError("sqlite_query_only_flag_rejected")
        connection = self._open(kind, initial_read_only=query_only is True)
        if query_only is None:
            return connection
        if query_only is False and kind in self._physical_read_only:
            raise SQLiteLifecycleError(
                "sqlite_read_only_connection_upgrade_rejected:" + kind
            )
        expected = 1 if query_only else 0
        with self._lock:
            connection.execute(f"PRAGMA query_only = {expected}")
            actual = int(connection.execute("PRAGMA query_only").fetchone()[0])
        if actual != expected:
            raise SQLiteLifecycleError(
                "sqlite_query_only_mode_unavailable:" + kind
            )
        return connection

    def generation(self, kind: DatabaseKind) -> DatabaseGeneration:
        self._open(kind)
        with self._lock:
            return self._generations[kind]

    @contextmanager
    def transaction(self, kind: DatabaseKind) -> Iterator[sqlite3.Connection]:
        connection = self._open(kind)
        if kind in self._physical_read_only:
            raise SQLiteLifecycleError(
                "sqlite_read_only_transaction_rejected:" + kind
            )
        with self._lock:
            if connection.in_transaction:
                raise SQLiteLifecycleError("nested_sqlite_transaction_rejected")
            connection.execute("BEGIN IMMEDIATE")
            transaction_completed = False
            try:
                yield connection
                connection.execute("COMMIT")
                transaction_completed = True
            finally:
                if not transaction_completed and connection.in_transaction:
                    connection.execute("ROLLBACK")

    def integrity_check(self, kind: DatabaseKind) -> DatabaseIntegrityResult:
        connection = self._open(kind)
        with self._lock:
            rows = tuple(str(row[0]) for row in connection.execute("PRAGMA integrity_check"))
            foreign = tuple(str(tuple(row)) for row in connection.execute("PRAGMA foreign_key_check"))
        details = rows + foreign
        return DatabaseIntegrityResult(kind=kind, ok=rows == ("ok",) and not foreign, details=details)

    def checkpoint(self, kind: DatabaseKind, *, mode: str = "PASSIVE") -> tuple[int, int, int]:
        if mode not in {"PASSIVE", "FULL", "RESTART", "TRUNCATE"}:
            raise ValueError("sqlite_checkpoint_mode_invalid")
        connection = self._open(kind)
        with self._lock:
            row = connection.execute(f"PRAGMA wal_checkpoint({mode})").fetchone()
        return int(row[0]), int(row[1]), int(row[2])

    def incremental_vacuum(self, kind: DatabaseKind, pages: int = 128) -> None:
        if type(pages) is not int or pages <= 0:
            raise ValueError("sqlite_vacuum_pages_invalid")
        connection = self._open(kind)
        with self._lock:
            connection.execute(f"PRAGMA incremental_vacuum({pages})")

    def create_known_good_backup(
        self,
        kind: DatabaseKind,
        *,
        model_generation_id: str = "",
        model_generation_manifest_sha256: str = "",
        canonical_state_digest: str = "",
    ) -> DatabaseBackupArtifact:
        """Create and validate one immutable SQLite-native backup artifact."""
        if kind not in {"model", "candidate", "cache"}:
            raise ValueError("sqlite_database_kind_invalid")
        model_fields = (
            model_generation_id,
            model_generation_manifest_sha256,
            canonical_state_digest,
        )
        if kind == "model":
            if any(
                type(value) is not str
                or len(value) != 64
                or any(ch not in "0123456789abcdef" for ch in value)
                for value in model_fields
            ):
                raise ValueError("sqlite_model_backup_generation_identity_required")
        elif any(model_fields):
            raise ValueError("sqlite_non_model_backup_generation_identity_rejected")
        with self._lock:
            connection = self._open(kind)
            path, _statements, _pragmas, app_id, user_version, digest = self._database_spec(kind)
            source_identity = self._supported_existing_identity_snapshot(
                connection,
                kind=kind,
                application_id=app_id,
                schema_version=user_version,
                schema_digest=digest,
            )
            created_ns = time.time_ns()
            backup_root = path.parent / _KNOWN_GOOD_BACKUP_DIRECTORY
            backup_root.mkdir(parents=True, exist_ok=True)
            backup_name = (
                f"{path.name}.{kind}.schema{user_version}."
                f"generation-{source_identity['generation_id']}.{created_ns}.sqlite3"
            )
            backup_path = backup_root / backup_name
            temporary_path = backup_root / (
                backup_name + f".tmp-{os.getpid()}-{time.time_ns()}"
            )
            backup_connection = sqlite3.connect(temporary_path, isolation_level=None)
            try:
                connection.backup(backup_connection)
                self._validate_sqlite_backup_identity(
                    backup_connection, kind=kind, source_identity=source_identity,
                )
            except (OSError, sqlite3.Error, SQLiteLifecycleError):
                backup_connection.close()
                temporary_path.unlink(missing_ok=True)
                raise
            else:
                backup_connection.close()
            durable_replace_regular_file(temporary_path, backup_path)
            backup_sha256 = self._sha256_file(backup_path)
            return DatabaseBackupArtifact(
                kind=kind,
                source_database_path=str(path),
                backup_path=str(backup_path),
                backup_sha256=backup_sha256,
                schema_version=user_version,
                schema_digest=digest,
                database_generation_id=str(source_identity["generation_id"]),
                created_ns=created_ns,
                model_generation_id=model_generation_id,
                model_generation_manifest_sha256=model_generation_manifest_sha256,
                canonical_state_digest=canonical_state_digest,
            )

    @staticmethod
    def _copy_backup_to_temporary_database(
        source_path: Path, destination_path: Path,
    ) -> None:
        source = sqlite3.connect(source_path, isolation_level=None)
        target = sqlite3.connect(destination_path, isolation_level=None)
        try:
            source.backup(target)
        finally:
            target.close()
            source.close()

    def validate_known_good_backup(
        self, artifact: DatabaseBackupArtifact,
    ) -> dict[str, object]:
        """Validate one backup artifact without mutating current database state."""
        if type(artifact) is not DatabaseBackupArtifact:
            raise TypeError("database_backup_artifact_required")
        kind = artifact.kind
        with self._lock:
            path, _statements, _pragmas, app_id, user_version, digest = self._database_spec(kind)
            if (
                artifact.source_database_path != str(path)
                or artifact.schema_version != user_version
                or artifact.schema_digest != digest
            ):
                raise SQLiteLifecycleError("sqlite_backup_restore_identity_mismatch")
            backup_path = Path(artifact.backup_path)
            if (
                path_contains_filesystem_alias(backup_path)
                or not backup_path.is_file()
                or self._sha256_file(backup_path) != artifact.backup_sha256
            ):
                raise SQLiteLifecycleError("sqlite_backup_restore_artifact_invalid")
            backup_connection = sqlite3.connect(backup_path, isolation_level=None)
            try:
                source_identity = self._supported_existing_identity_snapshot(
                    backup_connection,
                    kind=kind,
                    application_id=app_id,
                    schema_version=user_version,
                    schema_digest=digest,
                )
                self._validate_sqlite_backup_identity(
                    backup_connection, kind=kind, source_identity=source_identity,
                )
            finally:
                backup_connection.close()
            if str(source_identity["generation_id"]) != artifact.database_generation_id:
                raise SQLiteLifecycleError("sqlite_backup_restore_generation_mismatch")
            return dict(source_identity)

    def restore_known_good_backup(
        self,
        artifact: DatabaseBackupArtifact,
        *,
        rollback_artifact: DatabaseBackupArtifact | None = None,
    ) -> DatabaseGeneration:
        """Restore one validated backup under quiescent lifecycle ownership.

        The caller remains responsible for domain-semantic validation after the
        physical restore. This method validates SQLite identity/integrity and
        automatically reinstates a pre-restore known-good backup if installation
        or reopen validation fails.
        """
        if type(artifact) is not DatabaseBackupArtifact:
            raise TypeError("database_backup_artifact_required")
        kind = artifact.kind
        with self._lock:
            path, _statements, _pragmas, app_id, user_version, digest = self._database_spec(kind)
            backup_path = Path(artifact.backup_path)
            source_identity = self.validate_known_good_backup(artifact)

            if rollback_artifact is not None:
                if (
                    type(rollback_artifact) is not DatabaseBackupArtifact
                    or rollback_artifact.kind != kind
                ):
                    raise ValueError("sqlite_backup_rollback_artifact_invalid")
                pre_restore = rollback_artifact
            elif kind == "model":
                raise ValueError("sqlite_model_restore_rollback_artifact_required")
            else:
                # Preserve the pre-restore state using the same SQLite-native owner.
                pre_restore = self.create_known_good_backup(kind)
            try:
                self.checkpoint(kind, mode="TRUNCATE")
            except (sqlite3.Error, SQLiteLifecycleError) as exc:
                raise SQLiteLifecycleError("sqlite_backup_restore_quiescence_failed") from exc
            self.close()

            install_tmp = path.parent / (
                path.name + f".restore-tmp-{os.getpid()}-{time.time_ns()}"
            )
            try:
                self._copy_backup_to_temporary_database(backup_path, install_tmp)
                durable_replace_regular_file(install_tmp, path)
                Path(str(path) + "-wal").unlink(missing_ok=True)
                Path(str(path) + "-shm").unlink(missing_ok=True)
                restored = self._open(kind)
                restored_identity = self._supported_existing_identity_snapshot(
                    restored,
                    kind=kind,
                    application_id=app_id,
                    schema_version=user_version,
                    schema_digest=digest,
                )
                if str(restored_identity["generation_id"]) != artifact.database_generation_id:
                    raise SQLiteLifecycleError("sqlite_backup_restore_post_generation_mismatch")
                integrity = self.integrity_check(kind)
                if not integrity.ok:
                    raise SQLiteLifecycleError("sqlite_backup_restore_post_integrity_failed")
                return self.generation(kind)
            except (OSError, sqlite3.Error, SQLiteLifecycleError) as exc:
                install_tmp.unlink(missing_ok=True)
                self.close()
                if pre_restore is not None:
                    rollback_source = Path(pre_restore.backup_path)
                    rollback_tmp = path.parent / (
                        path.name + f".restore-rollback-{os.getpid()}-{time.time_ns()}"
                    )
                    self._copy_backup_to_temporary_database(rollback_source, rollback_tmp)
                    durable_replace_regular_file(rollback_tmp, path)
                    Path(str(path) + "-wal").unlink(missing_ok=True)
                    Path(str(path) + "-shm").unlink(missing_ok=True)
                    self._open(kind)
                raise SQLiteLifecycleError("sqlite_backup_restore_failed") from exc

    def close(self) -> None:
        with self._lock:
            close_failures: list[str] = []
            for kind, connection in (("model", self._model), ("candidate", self._candidate), ("cache", self._cache)):
                if connection is None:
                    continue
                try:
                    connection.close()
                except sqlite3.Error as exc:
                    close_failures.append(f"{kind}:{type(exc).__name__}")
            self._model = None
            self._candidate = None
            self._cache = None
            self._generations.clear()
            self._physical_read_only.clear()
            for kind in tuple(self._database_process_locks):
                try:
                    self._release_database_process_lock(kind)
                except OSError as exc:
                    close_failures.append(f"{kind}:process_lock:{type(exc).__name__}")
            if close_failures:
                raise SQLiteLifecycleError(
                    "sqlite_close_failed:" + ",".join(close_failures)
                )


_LIFECYCLE = SQLiteLifecycleOwner()


def sqlite_lifecycle() -> SQLiteLifecycleOwner:
    return _LIFECYCLE


__all__ = ("SQLiteLifecycleError", "SQLiteLifecycleOwner", "sqlite_lifecycle")
