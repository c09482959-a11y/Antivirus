"""Stage2636.11020 Phase 6 SQLite crash, corruption, and recovery gates."""
from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

import pytest

from Virus_Scan.core import jsonio
from Virus_Scan.storage import SQLiteLifecycleError, SQLiteLifecycleOwner


def _child(code: str, profiles: Path) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(Path.cwd())
    return subprocess.run(
        [sys.executable, "-c", code, str(profiles)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )


def _leave_hot_wal(profiles: Path, *, committed: bool) -> Path:
    if committed:
        transaction_body = """
connection.execute('BEGIN IMMEDIATE')
connection.execute(\"INSERT INTO database_metadata(key,value,updated_ns) VALUES('phase6_hot_wal','value',1)\")
connection.execute('COMMIT')
"""
    else:
        transaction_body = """
connection.execute('BEGIN IMMEDIATE')
connection.execute(\"INSERT INTO database_metadata(key,value,updated_ns) VALUES('phase6_baseline','durable',1)\")
connection.execute('COMMIT')
connection.execute('BEGIN IMMEDIATE')
connection.execute(\"INSERT INTO database_metadata(key,value,updated_ns) VALUES('phase6_hot_wal','value',1)\")
"""
    code = f"""
import os
import sys
from Virus_Scan.storage import SQLiteLifecycleOwner
owner = SQLiteLifecycleOwner()
owner.configure(sys.argv[1])
connection = owner.connection('model')
connection.execute('PRAGMA wal_autocheckpoint=0')
connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
{transaction_body}
os._exit(0)
"""
    result = _child(code, profiles)
    assert result.returncode == 0, result.stderr
    wal_path = Path(str(profiles / "model_state.sqlite3") + "-wal")
    assert wal_path.is_file() and wal_path.stat().st_size > 32
    return wal_path


def test_phase6_forced_exit_rolls_back_uncommitted_hot_wal(tmp_path: Path) -> None:
    profiles = tmp_path / "profiles"
    _leave_hot_wal(profiles, committed=False)

    owner = SQLiteLifecycleOwner()
    owner.configure(profiles)
    connection = owner.connection("model")
    baseline = connection.execute(
        "SELECT value FROM database_metadata WHERE key='phase6_baseline'"
    ).fetchone()
    assert baseline is not None and str(baseline[0]) == "durable"
    assert connection.execute(
        "SELECT 1 FROM database_metadata WHERE key='phase6_hot_wal'"
    ).fetchone() is None
    assert owner.integrity_check("model").ok is True
    owner.close()


def test_phase6_valid_committed_hot_wal_recovers_exact_state(tmp_path: Path) -> None:
    profiles = tmp_path / "profiles"
    _leave_hot_wal(profiles, committed=True)

    owner = SQLiteLifecycleOwner()
    owner.configure(profiles)
    row = owner.connection("model").execute(
        "SELECT value FROM database_metadata WHERE key='phase6_hot_wal'"
    ).fetchone()
    assert row is not None and str(row[0]) == "value"
    assert owner.integrity_check("model").ok is True
    owner.close()


def test_phase6_live_writer_allows_concurrent_owner_open_without_wal_file_race(
    tmp_path: Path,
) -> None:
    profiles = tmp_path / "profiles"
    writer = SQLiteLifecycleOwner()
    reader = SQLiteLifecycleOwner()
    writer.configure(profiles)
    reader.configure(profiles)
    writer_connection = writer.connection("model")
    writer_connection.execute("PRAGMA wal_autocheckpoint=0")
    writer_connection.execute(
        "INSERT INTO database_metadata(key,value,updated_ns) "
        "VALUES('phase6_live_wal','committed',1)"
    )
    writer_connection.execute("BEGIN IMMEDIATE")
    writer_connection.execute(
        "UPDATE database_metadata SET value='uncommitted' "
        "WHERE key='phase6_live_wal'"
    )
    try:
        reader_connection = reader.connection("model")
        visible = reader_connection.execute(
            "SELECT value FROM database_metadata WHERE key='phase6_live_wal'"
        ).fetchone()
        assert visible is not None and str(visible[0]) == "committed"
    finally:
        writer_connection.execute("ROLLBACK")
        reader.close()
        writer.close()


def test_phase6_raw_wal_validation_requires_exclusive_lifecycle_presence() -> None:
    import inspect

    helper_source = inspect.getsource(
        SQLiteLifecycleOwner._acquire_writable_lifecycle_presence
    )
    open_source = inspect.getsource(SQLiteLifecycleOwner._open)

    assert helper_source.index('exclusive_presence.acquire()') < helper_source.index(
        'validate_wal_before_recovery(database_path)'
    )
    assert helper_source.index('validate_wal_before_recovery(database_path)') < (
        helper_source.index('ResourceFileLock(path=presence_path, writable=False)')
    )
    assert 'validate_wal_before_recovery(path)' not in open_source
    assert open_source.index('self._acquire_writable_lifecycle_presence(kind, path)') < (
        open_source.index('sqlite3.connect(')
    )


@pytest.mark.parametrize("mutation", ["truncate", "checksum"])
def test_phase6_damaged_hot_wal_cannot_fall_back_to_stale_main_database(
    tmp_path: Path, mutation: str,
) -> None:
    profiles = tmp_path / "profiles"
    wal_path = _leave_hot_wal(profiles, committed=True)
    payload = bytearray(wal_path.read_bytes())
    if mutation == "truncate":
        wal_path.write_bytes(payload[: len(payload) // 2])
        expected = "sqlite_wal_frame_truncated"
    else:
        payload[-1] ^= 0x01
        wal_path.write_bytes(payload)
        expected = "sqlite_wal_frame_checksum_invalid"

    owner = SQLiteLifecycleOwner()
    owner.configure(profiles)
    with pytest.raises(SQLiteLifecycleError, match=expected):
        owner.connection("model")


def test_phase6_busy_lock_timeout_is_bounded_and_rolls_back(tmp_path: Path) -> None:
    profiles = tmp_path / "profiles"
    first = SQLiteLifecycleOwner()
    second = SQLiteLifecycleOwner()
    first.configure(profiles)
    second.configure(profiles)
    first_connection = first.connection("model")
    second_connection = second.connection("model")
    second_connection.execute("PRAGMA busy_timeout=50")
    first_connection.execute("BEGIN IMMEDIATE")
    started = time.perf_counter()
    try:
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            with second.transaction("model") as transaction:
                transaction.execute(
                    "INSERT INTO database_metadata(key,value,updated_ns) VALUES('phase6_lock','bad',1)"
                )
        assert time.perf_counter() - started < 1.0
        assert second_connection.in_transaction is False
        assert second_connection.execute(
            "SELECT 1 FROM database_metadata WHERE key='phase6_lock'"
        ).fetchone() is None
    finally:
        first_connection.execute("ROLLBACK")
        first.close()
        second.close()


def test_phase6_database_full_rolls_back_without_partial_row(tmp_path: Path) -> None:
    owner = SQLiteLifecycleOwner()
    owner.configure(tmp_path / "profiles")
    connection = owner.connection("cache")
    connection.execute("CREATE TABLE phase6_fill(payload BLOB NOT NULL)")
    page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
    connection.execute(f"PRAGMA max_page_count={page_count + 1}")

    with pytest.raises(sqlite3.OperationalError, match="full"):
        with owner.transaction("cache") as transaction:
            transaction.execute(
                "INSERT INTO phase6_fill(payload) VALUES(zeroblob(1048576))"
            )
    assert connection.in_transaction is False
    assert connection.execute("SELECT COUNT(*) FROM phase6_fill").fetchone()[0] == 0
    owner.close()


def test_phase6_invalid_database_root_fails_before_creating_state(tmp_path: Path) -> None:
    blocked_parent = tmp_path / "blocked"
    blocked_parent.write_text("not a directory", encoding="utf-8")
    owner = SQLiteLifecycleOwner()
    with pytest.raises(NotADirectoryError):
        owner.configure(blocked_parent / "profiles")
    assert not (blocked_parent / "profiles" / "model_state.sqlite3").exists()


def test_phase6_main_database_corruption_is_rejected(tmp_path: Path) -> None:
    profiles = tmp_path / "profiles"
    first = SQLiteLifecycleOwner()
    first.configure(profiles)
    database = first.paths().model_state
    first.connection("model")
    first.checkpoint("model", mode="TRUNCATE")
    first.close()
    payload = bytearray(database.read_bytes())
    payload[:16] = b"not sqlite data!"
    database.write_bytes(payload)

    second = SQLiteLifecycleOwner()
    second.configure(profiles)
    with pytest.raises(SQLiteLifecycleError, match="sqlite_open_failed:model"):
        second.connection("model")


def test_phase6_checkpoint_vacuum_foreign_keys_and_generation_restart(tmp_path: Path) -> None:
    profiles = tmp_path / "profiles"
    first = SQLiteLifecycleOwner()
    first.configure(profiles)
    first_generation = first.generation("model").generation_id
    assert first.integrity_check("model").ok is True
    assert first.checkpoint("model", mode="TRUNCATE")[0] in (0, 1)
    first.incremental_vacuum("model", pages=1)
    first.close()

    second = SQLiteLifecycleOwner()
    second.configure(profiles)
    connection = second.connection("model")
    assert second.generation("model").generation_id == first_generation
    status_rows = connection.execute(
        "SELECT generation_id,status FROM database_generations"
    ).fetchall()
    statuses = {str(row[0]): str(row[1]) for row in status_rows}
    assert statuses == {first_generation: "active"}
    assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    assert second.integrity_check("model").ok is True
    second.close()


def test_phase6_jsonio_has_no_superseded_profile_json_owner() -> None:
    source = Path(jsonio.__file__).read_text(encoding="utf-8")
    obsolete_tokens = (
        "_validate_persistent_json_batch",
        "_validate_json_file",
        "runtime_worker_shared_persistence_writes_disabled",
        "profiles_dir as _owned_profiles_dir",
        "_DEFAULT_ENGINE_VALUES",
        "DEFAULT_ENGINES",
        "_PROFILES_DIR_VALUE",
        "_PROFILES_DIR_TEXT",
        "_PROFILES_DIR_REASON",
        "PROFILES_DIR",
        "_PROFILE_FILE_LOCK_VALUE",
        "PROFILE_FILE_LOCK",
        "str.__add__(engine_text, '.json')",
    )
    for token in obsolete_tokens:
        assert token not in source, token
