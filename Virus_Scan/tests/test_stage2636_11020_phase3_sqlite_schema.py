from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import sqlite3

import pytest

from Virus_Scan.models.profiles.snapshots import default_engine_profile, default_extension_baseline
from Virus_Scan.models.profiles.schema_versions import PROFILE_LEARNING_TRANSACTION_SCHEMA_VERSION
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision
from Virus_Scan.tests.support.scan_cache_fixtures import verified_scan_cache_identity
from Virus_Scan.storage import (
    AuthoritativeModelStateOwner, ModelStateRepository, ScanCacheRepository,
    SQLiteLifecycleError, SQLiteLifecycleOwner,
)
from Virus_Scan.storage.sqlite_schema import CACHE_SCHEMA_DIGEST, MODEL_SCHEMA_DIGEST


def _owner(tmp_path: Path) -> SQLiteLifecycleOwner:
    owner = SQLiteLifecycleOwner()
    owner.configure(tmp_path / "profiles")
    return owner


def _tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0]) for row in connection.execute(
            "SELECT name FROM sqlite_schema WHERE type='table'"
        )
    }


def test_phase3_model_and_cache_have_distinct_exact_authority_domains(tmp_path: Path) -> None:
    owner = _owner(tmp_path)
    model = owner.connection("model")
    cache = owner.connection("cache")

    assert owner.paths().model_state.name == "model_state.sqlite3"
    assert owner.paths().scan_cache.name == "scan_cache.sqlite3"
    assert owner.paths().model_state != owner.paths().scan_cache
    assert {str(row[1]) for row in model.execute("PRAGMA database_list")} == {"main"}
    assert {str(row[1]) for row in cache.execute("PRAGMA database_list")} == {"main"}
    assert "profile_engines" in _tables(model)
    assert "learning_decisions" in _tables(model)
    assert "cache_contents" not in _tables(model)
    assert "cache_contents" in _tables(cache)
    assert "cache_semantic_results" in _tables(cache)
    assert "profile_engines" not in _tables(cache)

    assert model.execute("SELECT value FROM database_metadata WHERE key='schema_digest'").fetchone()[0] == MODEL_SCHEMA_DIGEST
    assert cache.execute("SELECT value FROM database_metadata WHERE key='schema_digest'").fetchone()[0] == CACHE_SCHEMA_DIGEST
    owner.close()


def test_phase3_lifecycle_enforces_required_pragmas_and_integrity(tmp_path: Path) -> None:
    owner = _owner(tmp_path)
    for kind in ("model", "cache"):
        generation = owner.generation(kind)
        assert generation.journal_mode == "wal"
        assert generation.foreign_keys is True
        assert generation.synchronous == 2
        assert generation.auto_vacuum == 2
        assert generation.busy_timeout_ms == 5000
        assert len(generation.schema_digest) == 64
        assert owner.integrity_check(kind).ok is True
        assert owner.checkpoint(kind, mode="PASSIVE")[0] in (0, 1)
    owner.incremental_vacuum("model", pages=1)
    owner.incremental_vacuum("cache", pages=1)
    owner.close()


def _rewrite_auto_vacuum_mode(path: Path, mode: str) -> None:
    connection = sqlite3.Connection(path, isolation_level=None)
    try:
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute(f"PRAGMA auto_vacuum = {mode}")
        if mode == "NONE":
            connection.execute("VACUUM")
        assert str(connection.execute("PRAGMA auto_vacuum").fetchone()[0]) == {
            "NONE": "0",
            "FULL": "1",
        }[mode]
    finally:
        connection.close()


def test_phase3_existing_none_auto_vacuum_is_backup_migrated_to_incremental(tmp_path: Path) -> None:
    profiles = tmp_path / "profiles"
    first = SQLiteLifecycleOwner()
    first.configure(profiles)
    generation_before = first.generation("model").generation_id
    model_path = first.paths().model_state
    first.close()

    _rewrite_auto_vacuum_mode(model_path, "NONE")

    migrated = SQLiteLifecycleOwner()
    migrated.configure(profiles)
    generation_after = migrated.generation("model")
    assert generation_after.auto_vacuum == 2
    assert generation_after.generation_id == generation_before
    connection = migrated.connection("model")
    metadata = dict(connection.execute(
        "SELECT key,value FROM database_metadata WHERE key LIKE 'auto_vacuum_migration_%'"
    ))
    assert metadata["auto_vacuum_migration_contract"] == "auto_vacuum_incremental_migration_v1"
    assert metadata["auto_vacuum_migration_source_mode"] == "0"
    backup_digest = metadata["auto_vacuum_migration_backup_sha256"]
    assert len(backup_digest) == 64
    backup_path = profiles / ".sqlite_migration_backups" / metadata["auto_vacuum_migration_backup_file"]
    assert backup_path.is_file()
    backup_connection = sqlite3.Connection(backup_path)
    try:
        assert backup_connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert backup_connection.execute("PRAGMA foreign_key_check").fetchone() is None
    finally:
        backup_connection.close()
    migrated.close()


def test_phase3_existing_full_auto_vacuum_switches_to_incremental_without_backup(tmp_path: Path) -> None:
    profiles = tmp_path / "profiles"
    first = SQLiteLifecycleOwner()
    first.configure(profiles)
    model_path = first.paths().model_state
    generation_before = first.generation("model").generation_id
    first.close()

    _rewrite_auto_vacuum_mode(model_path, "FULL")

    migrated = SQLiteLifecycleOwner()
    migrated.configure(profiles)
    generation_after = migrated.generation("model")
    assert generation_after.auto_vacuum == 2
    assert generation_after.generation_id == generation_before
    metadata = dict(migrated.connection("model").execute(
        "SELECT key,value FROM database_metadata WHERE key LIKE 'auto_vacuum_migration_%'"
    ))
    assert metadata["auto_vacuum_migration_contract"] == "auto_vacuum_incremental_migration_v1"
    assert metadata["auto_vacuum_migration_source_mode"] == "1"
    assert metadata["auto_vacuum_migration_backup_file"] == ""
    assert metadata["auto_vacuum_migration_backup_sha256"] == ""
    assert not (profiles / ".sqlite_migration_backups").exists()
    migrated.close()



def test_phase3_incomplete_none_auto_vacuum_migration_requires_validated_recovery(tmp_path: Path) -> None:
    profiles = tmp_path / "profiles"
    first = SQLiteLifecycleOwner()
    first.configure(profiles)
    first.generation("model")
    model_path = first.paths().model_state
    first.close()

    _rewrite_auto_vacuum_mode(model_path, "NONE")
    migrated = SQLiteLifecycleOwner()
    migrated.configure(profiles)
    migrated.generation("model")
    migrated.close()

    connection = sqlite3.Connection(model_path, isolation_level=None)
    try:
        connection.execute(
            "UPDATE database_metadata SET value='prepared' "
            "WHERE key='auto_vacuum_migration_state'"
        )
        connection.execute(
            "DELETE FROM database_metadata WHERE key='auto_vacuum_migration_completed_ns'"
        )
    finally:
        connection.close()

    recovery = SQLiteLifecycleOwner()
    recovery.configure(profiles)
    with pytest.raises(SQLiteLifecycleError, match="sqlite_auto_vacuum_migration_recovery_required"):
        recovery.connection("model")
    recovery.close()


def test_phase3_incomplete_none_auto_vacuum_migration_rejects_backup_substitution(tmp_path: Path) -> None:
    profiles = tmp_path / "profiles"
    first = SQLiteLifecycleOwner()
    first.configure(profiles)
    first.generation("model")
    model_path = first.paths().model_state
    first.close()

    _rewrite_auto_vacuum_mode(model_path, "NONE")
    migrated = SQLiteLifecycleOwner()
    migrated.configure(profiles)
    metadata = dict(migrated.connection("model").execute(
        "SELECT key,value FROM database_metadata WHERE key LIKE 'auto_vacuum_migration_%'"
    ))
    migrated.close()

    backup_path = profiles / ".sqlite_migration_backups" / metadata["auto_vacuum_migration_backup_file"]
    with backup_path.open("r+b") as stream:
        stream.seek(-1, 2)
        original = stream.read(1)
        stream.seek(-1, 2)
        stream.write(bytes((original[0] ^ 0x01,)))

    connection = sqlite3.Connection(model_path, isolation_level=None)
    try:
        connection.execute(
            "UPDATE database_metadata SET value='prepared' "
            "WHERE key='auto_vacuum_migration_state'"
        )
        connection.execute(
            "DELETE FROM database_metadata WHERE key='auto_vacuum_migration_completed_ns'"
        )
    finally:
        connection.close()

    recovery = SQLiteLifecycleOwner()
    recovery.configure(profiles)
    with pytest.raises(SQLiteLifecycleError, match="sqlite_auto_vacuum_migration_recovery_backup_invalid"):
        recovery.connection("model")
    recovery.close()

def test_phase3_model_constraints_and_transaction_rollback_fail_closed(tmp_path: Path) -> None:
    owner = _owner(tmp_path)
    connection = owner.connection("model")
    before = connection.execute("SELECT count(*) FROM profile_engines").fetchone()[0]
    with pytest.raises(sqlite3.IntegrityError):
        with owner.transaction("model") as transaction:
            transaction.execute(
                "INSERT INTO profile_engines(engine_id,profile_scope,profile_schema_version,created_value,updated_value,generation_id) "
                "VALUES(?,?,?,?,?,?)",
                ("renpy", "default", 5, 0.0, 0.0, "missing-generation"),
            )
    assert connection.execute("SELECT count(*) FROM profile_engines").fetchone()[0] == before

    with owner.transaction("model") as transaction:
        with pytest.raises(SQLiteLifecycleError, match="nested_sqlite_transaction_rejected"):
            with owner.transaction("model"):
                pass
        transaction.execute(
            "INSERT INTO database_metadata(key,value,updated_ns) VALUES(?,?,?)",
            ("phase3", "committed", 1),
        )
    assert connection.execute("SELECT value FROM database_metadata WHERE key='phase3'").fetchone()[0] == "committed"
    owner.close()


def test_phase3_profile_repository_round_trip_is_relationally_decomposed(tmp_path: Path) -> None:
    owner = _owner(tmp_path)
    repository = ModelStateRepository(owner)
    profile = default_engine_profile("renpy")
    profile["extension_baselines"]["renpy/.rpy"] = default_extension_baseline("renpy/.rpy")

    with owner.transaction("model") as connection:
        repository.write_profile(connection, profile)

    loaded = repository.read_profile("renpy")
    assert loaded == profile
    connection = owner.connection("model")
    assert connection.execute("SELECT count(*) FROM profile_engines").fetchone()[0] == 1
    assert connection.execute("SELECT count(*) FROM profile_extensions").fetchone()[0] == 1
    assert connection.execute("SELECT count(*) FROM profile_extension_tag_evidence").fetchone()[0] == 1
    assert connection.execute("SELECT count(*) FROM profile_extension_chains").fetchone()[0] == 1
    assert connection.execute("SELECT count(*) FROM profile_extension_timeline").fetchone()[0] == 1
    assert connection.execute("SELECT count(*) FROM profile_contamination_state").fetchone()[0] == 1
    assert connection.execute("SELECT count(*) FROM profile_decision_history_state").fetchone()[0] == 1
    assert "profile_components" not in _tables(connection)
    owner.close()



def test_phase3_profile_scope_is_part_of_every_profile_identity(tmp_path: Path) -> None:
    owner = _owner(tmp_path)
    repository = ModelStateRepository(owner)
    first = default_engine_profile("renpy")
    second = default_engine_profile("renpy")
    first["extension_baselines"]["renpy/.rpy"] = default_extension_baseline("renpy/.rpy")
    second["extension_baselines"]["renpy/.rpyc"] = default_extension_baseline("renpy/.rpyc")

    with owner.transaction("model") as connection:
        repository.write_profile(connection, first, profile_scope="project-a")
        repository.write_profile(connection, second, profile_scope="project-b")

    assert repository.read_profile("renpy", profile_scope="project-a") == first
    assert repository.read_profile("renpy", profile_scope="project-b") == second
    connection = owner.connection("model")
    assert connection.execute("SELECT count(*) FROM profile_engines").fetchone()[0] == 2
    assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    owner.close()


def test_phase3_learning_transaction_round_trip_uses_one_decision_and_target_owner(tmp_path: Path) -> None:
    owner = _owner(tmp_path)
    repository = ModelStateRepository(owner)
    profile = default_engine_profile("renpy")
    decision = accepted_learning_decision(
        target_names=("profile", "clustering"), observation_id="phase3-sqlite-transaction",
    )
    targets = {
        target: {"status": "succeeded", "attempts": 1, "reason": "", "output": {}}
        for target in decision.permitted_model_targets
    }
    transaction = {
        "schema_version": PROFILE_LEARNING_TRANSACTION_SCHEMA_VERSION,
        "replay_key": decision.replay_key,
        "observation_id": decision.observation_id,
        "observation_digest": decision.observation_digest,
        "decision_ordinal": decision.decision_ordinal,
        "decision": decision.to_record(),
        "context_key": "renpy/.test",
        "diversity_key": "phase3-diversity",
        "target_order": list(decision.permitted_model_targets),
        "targets": targets,
        "status": "complete",
        "completed_targets": len(targets),
        "failed_targets": 0,
        "authoritative_transaction_id": (
            AuthoritativeModelStateOwner.transaction_identity(
                transaction_kind="learning_commit",
                replay_key=decision.replay_key,
            )
        ),
    }
    profile["model_state"]["learning_transactions"][decision.replay_key] = transaction

    authority = AuthoritativeModelStateOwner(owner)
    transaction_id = authority.commit(
        profiles=(profile,), transaction_kind="learning_commit",
        replay_key=decision.replay_key,
    )

    assert transaction_id == transaction["authoritative_transaction_id"]
    assert repository.read_profile("renpy") == profile
    connection = owner.connection("model")
    row = connection.execute(
        "SELECT replay_key,content_identity_status,status FROM learning_decisions"
    ).fetchone()
    assert tuple(row) == (decision.replay_key, "unavailable", "complete")
    assert connection.execute("SELECT count(*) FROM learning_targets").fetchone()[0] == 2
    owner.close()


def test_phase3_existing_schema_digest_mismatch_fails_closed(tmp_path: Path) -> None:
    profiles = tmp_path / "profiles"
    first = SQLiteLifecycleOwner()
    first.configure(profiles)
    path = first.paths().model_state
    first.connection("model")
    first.close()

    direct = sqlite3.Connection(path)
    direct.execute(
        "UPDATE database_metadata SET value=? WHERE key='schema_digest'",
        ("0" * 64,),
    )
    direct.commit()
    direct.close()

    second = SQLiteLifecycleOwner()
    second.configure(profiles)
    with pytest.raises(SQLiteLifecycleError, match="sqlite_schema_digest_mismatch"):
        second.connection("model")


def test_phase3_reopen_preserves_existing_database_generations(tmp_path: Path) -> None:
    profiles = tmp_path / "profiles"
    first = SQLiteLifecycleOwner()
    first.configure(profiles)
    model_generation = first.generation("model").generation_id
    cache_generation = first.generation("cache").generation_id
    first.close()

    second = SQLiteLifecycleOwner()
    second.configure(profiles)
    connection = second.connection("model")
    assert second.generation("model").generation_id == model_generation
    assert second.generation("cache").generation_id == cache_generation
    statuses = {str(row[0]): str(row[1]) for row in connection.execute(
        "SELECT generation_id,status FROM database_generations"
    )}
    assert statuses == {model_generation: "active"}
    second.close()


def test_phase3_missing_persisted_generation_fails_closed(tmp_path: Path) -> None:
    profiles = tmp_path / "profiles"
    first = SQLiteLifecycleOwner()
    first.configure(profiles)
    path = first.paths().scan_cache
    first.connection("cache")
    first.close()

    direct = sqlite3.Connection(path)
    direct.execute(
        "DELETE FROM database_metadata WHERE key='current_generation_id'"
    )
    direct.commit()
    direct.close()

    second = SQLiteLifecycleOwner()
    second.configure(profiles)
    with pytest.raises(SQLiteLifecycleError, match="sqlite_generation_metadata_missing"):
        second.connection("cache")

def test_phase3_cache_repository_uses_exact_content_and_semantic_identity(tmp_path: Path) -> None:
    owner = _owner(tmp_path)
    repository = ScanCacheRepository(owner)
    repository.configure(owner.paths().profiles_dir, enabled=True)
    repository.configure_retention(
        max_contents=10, max_aliases_per_content=2, max_results_per_content=3,
        max_total_bytes=1024 * 1024, max_age_seconds=3600,
    )
    content = "a" * 64
    identity = verified_scan_cache_identity()
    changed_identity = verified_scan_cache_identity(policy_seed="9")
    result = {"file": "original", "classification": "clean", "schema_version": "result_v1"}
    assert repository.put_result(
        content_sha256=content, content_size=7, canonical_path="/a/sample.bin",
        file_name="sample.bin", execution_identity=identity, result=result,
    ) is True

    hit = repository.get_result(
        content_sha256=content,
        execution_identity=identity,
        canonical_path="/b/sample.bin",
        file_name="sample.bin",
        content_size=7,
    )
    assert hit is not None
    assert hit.result == result
    assert repository.get_result(
        content_sha256=content,
        execution_identity=changed_identity,
        canonical_path="/c/sample.bin",
        file_name="sample.bin",
        content_size=7,
    ) is None
    connection = owner.connection("cache")
    assert connection.execute("SELECT count(*) FROM cache_contents").fetchone()[0] == 1
    assert connection.execute("SELECT count(*) FROM cache_aliases").fetchone()[0] == 2
    assert connection.execute("SELECT access_count FROM cache_semantic_results").fetchone()[0] == 1
    owner.close()


def test_phase3_lifecycle_owner_owns_cache_query_only_mode(tmp_path: Path) -> None:
    owner = SQLiteLifecycleOwner()
    owner.configure(tmp_path / "profiles")
    writable = owner.connection("cache", query_only=False)
    assert writable.execute("PRAGMA query_only").fetchone()[0] == 0
    reader = owner.connection("cache", query_only=True)
    assert reader is writable
    assert reader.execute("PRAGMA query_only").fetchone()[0] == 1
    writable_again = owner.connection("cache", query_only=False)
    assert writable_again is writable
    assert writable_again.execute("PRAGMA query_only").fetchone()[0] == 0
    owner.close()


def test_phase3_initial_query_only_connection_is_physical_read_only_and_nonmutating(
    tmp_path: Path,
) -> None:
    profiles = tmp_path / "profiles"
    writer = SQLiteLifecycleOwner()
    writer.configure(profiles)
    database_path = writer.paths().scan_cache
    writer.connection("cache")
    writer.checkpoint("cache", mode="TRUNCATE")
    writer.close()
    before_bytes = database_path.read_bytes()
    before_digest = hashlib.sha256(before_bytes).hexdigest()

    reader = SQLiteLifecycleOwner()
    reader.configure(profiles, create=False)
    connection = reader.connection("cache", query_only=True)
    assert connection.execute("PRAGMA query_only").fetchone()[0] == 1
    assert reader.generation("cache").auto_vacuum == 2
    with pytest.raises(SQLiteLifecycleError, match="sqlite_read_only_connection_upgrade_rejected"):
        reader.connection("cache", query_only=False)
    connection.execute("PRAGMA query_only = OFF")
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        connection.execute("CREATE TABLE forbidden_reader_write(value INTEGER)")
    reader.close()

    assert hashlib.sha256(database_path.read_bytes()).hexdigest() == before_digest
    assert database_path.read_bytes() == before_bytes


def test_phase3_initial_query_only_connection_rejects_required_migration_without_mutation(
    tmp_path: Path,
) -> None:
    profiles = tmp_path / "profiles"
    writer = SQLiteLifecycleOwner()
    writer.configure(profiles)
    database_path = writer.paths().scan_cache
    writer.connection("cache")
    writer.checkpoint("cache", mode="TRUNCATE")
    writer.close()
    _rewrite_auto_vacuum_mode(database_path, "NONE")
    repair = sqlite3.Connection(database_path, isolation_level=None)
    try:
        assert str(repair.execute("PRAGMA journal_mode = WAL").fetchone()[0]).lower() == "wal"
    finally:
        repair.close()
    before_bytes = database_path.read_bytes()
    before_digest = hashlib.sha256(before_bytes).hexdigest()

    reader = SQLiteLifecycleOwner()
    reader.configure(profiles, create=False)
    with pytest.raises(
        SQLiteLifecycleError, match="sqlite_read_only_auto_vacuum_migration_required",
    ):
        reader.connection("cache", query_only=True)
    reader.close()

    assert hashlib.sha256(database_path.read_bytes()).hexdigest() == before_digest
    assert database_path.read_bytes() == before_bytes
    verify = sqlite3.Connection(database_path, isolation_level=None)
    try:
        assert int(verify.execute("PRAGMA auto_vacuum").fetchone()[0]) == 0
    finally:
        verify.close()


def test_phase3_only_lifecycle_owner_executes_production_pragma_statements() -> None:
    offenders: list[str] = []
    root = Path("Virus_Scan")
    allowed = {"Virus_Scan/storage/sqlite_lifecycle.py"}
    for path in root.rglob("*.py"):
        relative = path.as_posix()
        if "/tests/" in relative:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != "execute" or not node.args:
                continue
            argument = node.args[0]
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                if argument.value.lstrip().upper().startswith("PRAGMA ") and relative not in allowed:
                    offenders.append(relative + ":" + str(node.lineno))
            elif isinstance(argument, ast.JoinedStr):
                prefix = ""
                if argument.values and isinstance(argument.values[0], ast.Constant):
                    first = argument.values[0].value
                    if isinstance(first, str):
                        prefix = first
                if prefix.lstrip().upper().startswith("PRAGMA ") and relative not in allowed:
                    offenders.append(relative + ":" + str(node.lineno))
    assert offenders == []


def test_phase3_only_lifecycle_owner_opens_production_sqlite_connections() -> None:
    offenders: list[str] = []
    root = Path("Virus_Scan")
    allowed = {"Virus_Scan/storage/sqlite_lifecycle.py"}
    for path in root.rglob("*.py"):
        relative = path.as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "sqlite3" and node.func.attr == "connect":
                if relative not in allowed:
                    offenders.append(relative + ":" + str(node.lineno))
    assert offenders == []
