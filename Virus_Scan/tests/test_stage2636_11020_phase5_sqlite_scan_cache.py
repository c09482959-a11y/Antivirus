from __future__ import annotations

from pathlib import Path
import sqlite3

import pytest

from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture
from Virus_Scan.contracts.artifact_read_snapshot import attach_artifact_read_record
from Virus_Scan.contracts.scan_cache_fingerprint import (
    SCAN_CACHE_RESULT_SCHEMA_VERSION,
    scan_cache_options_fingerprint,
)
from Virus_Scan.core.cache import pre_scan_cache_lookup
from Virus_Scan.storage.scan_cache_result_writer.scan_cache_result_writer import ScanCacheResultWriter
from Virus_Scan.storage import (
    ScanCacheRepository,
    SQLiteLifecycleError,
    SQLiteLifecycleOwner,
    scan_cache_repository,
    sqlite_lifecycle,
)
from Virus_Scan.tests.support.scan_cache_fixtures import (
    disabled_scan_cache_identity,
    verified_scan_cache_identity,
)
from Virus_Scan.tests.support.native_filesystem_alias import create_native_directory_alias


def _result(path: Path) -> dict[str, object]:
    return {
        "file": str(path),
        "path": str(path),
        "classification": "benign_clean",
        "score": 0.0,
        "tags": ["binary_file"],
        "scan_integrity": {"allow_learning": True},
        "learn_eligible": True,
    }


def _repository(root: Path) -> tuple[SQLiteLifecycleOwner, ScanCacheRepository]:
    lifecycle = SQLiteLifecycleOwner()
    repository = ScanCacheRepository(lifecycle)
    repository.configure(root, enabled=True)
    return lifecycle, repository


def test_phase5_same_content_aliases_share_one_semantic_result(tmp_path: Path) -> None:
    lifecycle, repository = _repository(tmp_path / "profiles")
    identity = verified_scan_cache_identity()
    sha256 = "1" * 64
    try:
        assert repository.put_result(
            content_sha256=sha256,
            content_size=8,
            canonical_path=str(tmp_path / "first.bin"),
            file_name="first.bin",
            execution_identity=identity,
            result={"classification": "benign_clean", "tags": ["binary_file"]},
        ) is True
        hit = repository.get_result(
            content_sha256=sha256,
            execution_identity=identity,
            canonical_path=str(tmp_path / "second.bin"),
            file_name="second.bin",
            content_size=8,
        )
        assert hit is not None
        assert hit.content_sha256 == sha256
        stats = repository.stats()
        assert stats["contents"] == 1
        assert stats["results"] == 1
        assert stats["aliases"] == 2
        assert stats["execution_identities"] == 1
        assert stats["database_bytes"] > 0
        assert stats["wal_bytes"] >= 0
    finally:
        lifecycle.close()


def test_phase5_fast_fingerprint_lookup_is_bound_to_exact_payload(tmp_path: Path) -> None:
    lifecycle, repository = _repository(tmp_path / "profiles")
    identity = verified_scan_cache_identity()
    sha256 = "2" * 64
    fast = "3" * 64
    payload = {"size": 9, "mtime_ns": 10, "extension": ".bin"}
    try:
        assert repository.put_result(
            content_sha256=sha256,
            content_size=9,
            canonical_path=str(tmp_path / "payload.bin"),
            file_name="payload.bin",
            execution_identity=identity,
            result={"classification": "benign_clean", "tags": []},
            fast_fingerprint=fast,
            fast_fingerprint_payload=payload,
            stat_mtime_ns=10,
        ) is True
        hit = repository.get_by_fast_fingerprint(
            fast_fingerprint=fast,
            fast_fingerprint_payload=payload,
            execution_identity=identity,
            canonical_path=str(tmp_path / "alias.bin"),
            file_name="alias.bin",
            content_size=9,
            stat_mtime_ns=10,
        )
        assert hit is not None
        assert hit.source == "fast_fingerprint"
        assert repository.get_by_fast_fingerprint(
            fast_fingerprint=fast,
            fast_fingerprint_payload={**payload, "mtime_ns": 11},
            execution_identity=identity,
            canonical_path=str(tmp_path / "alias.bin"),
            file_name="alias.bin",
            content_size=9,
            stat_mtime_ns=11,
        ) is None
    finally:
        lifecycle.close()


def test_phase5_every_semantic_identity_drift_is_a_miss(tmp_path: Path) -> None:
    lifecycle, repository = _repository(tmp_path / "profiles")
    baseline = verified_scan_cache_identity()
    changed = verified_scan_cache_identity(alignment_seed="9")
    sha256 = "4" * 64
    try:
        assert scan_cache_options_fingerprint(baseline) != scan_cache_options_fingerprint(changed)
        repository.put_result(
            content_sha256=sha256,
            content_size=4,
            canonical_path=str(tmp_path / "payload.bin"),
            file_name="payload.bin",
            execution_identity=baseline,
            result={"classification": "benign_clean", "tags": []},
        )
        assert repository.get_result(
            content_sha256=sha256,
            execution_identity=changed,
            canonical_path=str(tmp_path / "payload.bin"),
            file_name="payload.bin",
            content_size=4,
        ) is None
    finally:
        lifecycle.close()


@pytest.mark.parametrize(
    ("column", "value"),
    (("result_sha256", "0" * 64), ("partial", 1), ("truncated", 1), ("integrity_status", "invalid")),
)
def test_phase5_corrupt_partial_or_truncated_rows_fail_closed_and_are_deleted(
    tmp_path: Path, column: str, value: object,
) -> None:
    lifecycle, repository = _repository(tmp_path / "profiles")
    identity = verified_scan_cache_identity()
    sha256 = "5" * 64
    digest = scan_cache_options_fingerprint(identity)
    try:
        repository.put_result(
            content_sha256=sha256,
            content_size=5,
            canonical_path=str(tmp_path / "payload.bin"),
            file_name="payload.bin",
            execution_identity=identity,
            result={"classification": "benign_clean", "tags": []},
        )
        lifecycle.connection("cache").execute(
            f"UPDATE cache_semantic_results SET {column}=? WHERE content_sha256=? AND identity_digest=?",
            (value, sha256, digest),
        )
        assert repository.get_result(
            content_sha256=sha256,
            execution_identity=identity,
            canonical_path=str(tmp_path / "payload.bin"),
            file_name="payload.bin",
            content_size=5,
        ) is None
        assert lifecycle.connection("cache").execute(
            "SELECT 1 FROM cache_semantic_results WHERE content_sha256=? AND identity_digest=?",
            (sha256, digest),
        ).fetchone() is None
    finally:
        lifecycle.close()


def test_phase5_retention_bounds_contents_aliases_results_age_and_bytes(tmp_path: Path) -> None:
    lifecycle, repository = _repository(tmp_path / "profiles")
    repository.configure_retention(
        max_contents=2,
        max_aliases_per_content=2,
        max_results_per_content=1,
        max_total_bytes=50_000,
        max_age_seconds=60,
    )
    first_identity = verified_scan_cache_identity()
    second_identity = verified_scan_cache_identity(alignment_seed="8")
    try:
        for index, sha256 in enumerate(("6" * 64, "7" * 64, "8" * 64)):
            repository.put_result(
                content_sha256=sha256,
                content_size=index + 1,
                canonical_path=str(tmp_path / f"{index}.bin"),
                file_name=f"{index}.bin",
                execution_identity=first_identity,
                result={"classification": "benign_clean", "tags": [], "index": index},
            )
        assert repository.stats()["contents"] == 2
        retained_sha = "8" * 64
        repository.put_result(
            content_sha256=retained_sha,
            content_size=3,
            canonical_path=str(tmp_path / "identity-two.bin"),
            file_name="identity-two.bin",
            execution_identity=second_identity,
            result={"classification": "benign_clean", "tags": [], "identity": 2},
        )
        for index in range(4):
            repository.get_result(
                content_sha256=retained_sha,
                execution_identity=second_identity,
                canonical_path=str(tmp_path / f"alias-{index}.bin"),
                file_name=f"alias-{index}.bin",
                content_size=3,
            )
        connection = lifecycle.connection("cache")
        assert connection.execute(
            "SELECT COUNT(*) FROM cache_aliases WHERE content_sha256=?", (retained_sha,)
        ).fetchone()[0] <= 2
        assert connection.execute(
            "SELECT COUNT(*) FROM cache_semantic_results WHERE content_sha256=?", (retained_sha,)
        ).fetchone()[0] <= 1
        connection.execute(
            "UPDATE cache_contents SET first_seen_ns=0,last_seen_ns=0 WHERE content_sha256=?",
            (retained_sha,),
        )
        repository.maintenance(force=False)
        assert connection.execute(
            "SELECT 1 FROM cache_contents WHERE content_sha256=?", (retained_sha,)
        ).fetchone() is None
        repository.configure_retention(
            max_contents=2,
            max_aliases_per_content=2,
            max_results_per_content=1,
            max_total_bytes=256,
            max_age_seconds=60,
        )
        assert repository.stats()["logical_bytes"] <= 256
    finally:
        lifecycle.close()


def test_phase5_cache_deletion_and_rebuild_cannot_change_model_truth(tmp_path: Path) -> None:
    root = tmp_path / "profiles"
    lifecycle, repository = _repository(root)
    identity = disabled_scan_cache_identity()
    try:
        model = lifecycle.connection("model")
        model.execute(
            "INSERT INTO database_metadata(key,value,updated_ns) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_ns=excluded.updated_ns",
            ("phase5_model_sentinel", "authoritative", 1),
        )
        repository.put_result(
            content_sha256="9" * 64,
            content_size=9,
            canonical_path=str(tmp_path / "payload.bin"),
            file_name="payload.bin",
            execution_identity=identity,
            result={"classification": "benign_clean", "tags": []},
        )
    finally:
        lifecycle.close()
    (root / "scan_cache.sqlite3").unlink()
    for suffix in ("-wal", "-shm"):
        candidate = root / ("scan_cache.sqlite3" + suffix)
        if candidate.exists():
            candidate.unlink()
    reopened = SQLiteLifecycleOwner()
    reopened.configure(root)
    try:
        row = reopened.connection("model").execute(
            "SELECT value FROM database_metadata WHERE key='phase5_model_sentinel'"
        ).fetchone()
        assert row is not None and row[0] == "authoritative"
        rebuilt = ScanCacheRepository(reopened)
        rebuilt.configure(root, enabled=True)
        assert rebuilt.stats()["contents"] == 0
    finally:
        reopened.close()


def test_phase5_reporting_store_and_core_lookup_use_one_sqlite_owner(tmp_path: Path) -> None:
    sample = tmp_path / "payload.bin"
    sample.write_bytes(b"phase5-cache-payload")
    repository = scan_cache_repository()
    repository.configure(tmp_path / "profiles", enabled=True)
    identity = verified_scan_cache_identity()
    try:
        result = _result(sample)
        attach_artifact_read_record(result, artifact_read_snapshot_fixture(sample))
        assert ScanCacheResultWriter(identity)(result) is True
        cached, sha256 = pre_scan_cache_lookup(artifact_read_snapshot_fixture(sample), execution_identity=identity)
        assert type(cached) is dict
        assert cached["cache_hit"] is True
        assert sha256
        connection = sqlite_lifecycle().connection("cache")
        assert connection.execute("SELECT access_count FROM cache_semantic_results").fetchone()[0] == 1
        assert ScanCacheResultWriter(identity)(cached) is True
        assert connection.execute("SELECT access_count FROM cache_semantic_results").fetchone()[0] == 2
        assert repository.stats()["contents"] == 1
        assert repository.stats()["results"] == 1
        assert not (tmp_path / "profiles" / "scan_cache.json").exists()
        assert (tmp_path / "profiles" / "scan_cache.sqlite3").exists()
    finally:
        repository.configure(tmp_path / "disabled", enabled=False)
        sqlite_lifecycle().close()


def test_phase5_storage_rejects_dict_subclasses_without_mapping_hooks(tmp_path: Path) -> None:
    class HostileDict(dict):
        touched = 0

        def items(self):  # pragma: no cover
            type(self).touched += 1
            raise AssertionError("items hook executed")

        def __iter__(self):  # pragma: no cover
            type(self).touched += 1
            raise AssertionError("iter hook executed")

    lifecycle, repository = _repository(tmp_path / "profiles")
    try:
        with pytest.raises(TypeError, match="scan_cache_json_value_rejected"):
            repository.put_result(
                content_sha256="a" * 64,
                content_size=1,
                canonical_path=str(tmp_path / "payload.bin"),
                file_name="payload.bin",
                execution_identity=disabled_scan_cache_identity(),
                result=HostileDict({"classification": "benign_clean"}),
            )
        assert HostileDict.touched == 0
    finally:
        lifecycle.close()



def test_phase5_process_reader_does_not_create_missing_profiles(tmp_path: Path) -> None:
    profiles = tmp_path / "missing" / "profiles"
    lifecycle = SQLiteLifecycleOwner()
    reader = ScanCacheRepository(lifecycle)
    with pytest.raises(SQLiteLifecycleError, match="sqlite_profiles_directory_missing"):
        reader.configure_reader(profiles)
    assert not profiles.exists()


def test_phase5_process_reader_rejects_symlinked_cache_database(tmp_path: Path) -> None:
    source_profiles = tmp_path / "source_profiles"
    source_lifecycle, _source = _repository(source_profiles)
    source_path = source_lifecycle.paths().scan_cache
    source_lifecycle.close()
    reader_profiles = create_native_directory_alias(
        tmp_path / "reader_profiles", source_path.parent,
    ).path
    lifecycle = SQLiteLifecycleOwner()
    reader = ScanCacheRepository(lifecycle)
    with pytest.raises(SQLiteLifecycleError, match="sqlite_profiles_directory_alias_rejected"):
        reader.configure_reader(reader_profiles)
    lifecycle.close()


def test_phase5_process_reader_is_query_only_and_parent_owns_hit_accounting(tmp_path: Path) -> None:
    root = tmp_path / "profiles"
    parent_lifecycle, parent = _repository(root)
    identity = verified_scan_cache_identity()
    sha256 = "b" * 64
    source_path = tmp_path / "source.bin"
    alias_path = tmp_path / "alias.bin"
    try:
        assert parent.put_result(
            content_sha256=sha256,
            content_size=6,
            canonical_path=str(source_path),
            file_name=source_path.name,
            execution_identity=identity,
            result={"classification": "benign_clean", "tags": ["binary_file"]},
            stat_mtime_ns=11,
        ) is True
        reader_lifecycle = SQLiteLifecycleOwner()
        reader = ScanCacheRepository(reader_lifecycle)
        try:
            reader.configure_reader(root)
            assert reader.enabled() is True
            assert reader.read_only() is True
            assert reader.writable() is False
            assert reader_lifecycle.connection("cache").execute("PRAGMA query_only").fetchone()[0] == 1
            hit = reader.get_result(
                content_sha256=sha256,
                execution_identity=identity,
                canonical_path=str(alias_path),
                file_name=alias_path.name,
                content_size=6,
                stat_mtime_ns=12,
            )
            assert hit is not None
            assert reader.put_result(
                content_sha256="c" * 64,
                content_size=1,
                canonical_path=str(tmp_path / "rejected.bin"),
                file_name="rejected.bin",
                execution_identity=identity,
                result={"classification": "benign_clean", "tags": []},
            ) is False
            connection = parent_lifecycle.connection("cache")
            assert connection.execute(
                "SELECT access_count FROM cache_semantic_results WHERE content_sha256=?",
                (sha256,),
            ).fetchone()[0] == 0
            assert connection.execute(
                "SELECT COUNT(*) FROM cache_aliases WHERE content_sha256=?",
                (sha256,),
            ).fetchone()[0] == 1
            assert parent.record_result_hit(
                content_sha256=sha256,
                execution_identity=identity,
                canonical_path=str(alias_path),
                file_name=alias_path.name,
                content_size=6,
                stat_mtime_ns=12,
            ) is True
            assert connection.execute(
                "SELECT access_count FROM cache_semantic_results WHERE content_sha256=?",
                (sha256,),
            ).fetchone()[0] == 1
            assert connection.execute(
                "SELECT COUNT(*) FROM cache_aliases WHERE content_sha256=?",
                (sha256,),
            ).fetchone()[0] == 2
        finally:
            reader_lifecycle.close()
    finally:
        parent_lifecycle.close()


def test_phase5_process_reader_rejects_corrupt_row_without_mutating_shared_cache(tmp_path: Path) -> None:
    root = tmp_path / "profiles"
    parent_lifecycle, parent = _repository(root)
    identity = verified_scan_cache_identity()
    sha256 = "d" * 64
    digest = scan_cache_options_fingerprint(identity)
    try:
        assert parent.put_result(
            content_sha256=sha256,
            content_size=4,
            canonical_path=str(tmp_path / "payload.bin"),
            file_name="payload.bin",
            execution_identity=identity,
            result={"classification": "benign_clean", "tags": []},
        ) is True
        parent_lifecycle.connection("cache").execute(
            "UPDATE cache_semantic_results SET result_sha256=? WHERE content_sha256=? AND identity_digest=?",
            ("0" * 64, sha256, digest),
        )
        reader_lifecycle = SQLiteLifecycleOwner()
        reader = ScanCacheRepository(reader_lifecycle)
        try:
            reader.configure_reader(root)
            assert reader.get_result(
                content_sha256=sha256,
                execution_identity=identity,
                canonical_path=str(tmp_path / "payload.bin"),
                file_name="payload.bin",
                content_size=4,
            ) is None
            assert parent_lifecycle.connection("cache").execute(
                "SELECT 1 FROM cache_semantic_results WHERE content_sha256=? AND identity_digest=?",
                (sha256, digest),
            ).fetchone() is not None
        finally:
            reader_lifecycle.close()
        assert parent.get_result(
            content_sha256=sha256,
            execution_identity=identity,
            canonical_path=str(tmp_path / "payload.bin"),
            file_name="payload.bin",
            content_size=4,
        ) is None
        assert parent_lifecycle.connection("cache").execute(
            "SELECT 1 FROM cache_semantic_results WHERE content_sha256=? AND identity_digest=?",
            (sha256, digest),
        ).fetchone() is None
    finally:
        parent_lifecycle.close()

def test_phase5_no_live_json_cache_owner_or_parallel_runtime_mapping() -> None:
    root = Path(__file__).resolve().parents[1]
    production = tuple(
        path for path in root.rglob("*.py")
        if "tests" not in path.parts and "__pycache__" not in path.parts
    )
    text = "\n".join(path.read_text(encoding="utf-8") for path in production)
    assert "scan_cache.json" not in text
    assert "def load_scan_cache" not in text
    assert "def flush_scan_cache" not in text
    assert "scan_cache_dirty" not in text
    assert "runtime_cache_by_name('SCAN_CACHE')" not in text
    assert "runtime_cache_by_name(\"SCAN_CACHE\")" not in text
    assert "profiles/scan_cache.sqlite3" in (
        root / "cli" / "arg_parser_builders.py"
    ).read_text(encoding="utf-8")
    assert SCAN_CACHE_RESULT_SCHEMA_VERSION == "scan_cache_result_record_v2"


def test_rev21_phase6_cache_hot_write_uses_incremental_accounting_not_full_reconciliation(
    tmp_path: Path,
) -> None:
    lifecycle, repository = _repository(tmp_path / "profiles")
    identity = verified_scan_cache_identity()
    connection = lifecycle.connection("cache")
    statements: list[str] = []
    connection.set_trace_callback(statements.append)
    try:
        assert repository.put_result(
            content_sha256="d" * 64,
            content_size=7,
            canonical_path=str(tmp_path / "incremental.bin"),
            file_name="incremental.bin",
            execution_identity=identity,
            result={"classification": "benign_clean", "tags": [], "phase": 6},
        ) is True
    finally:
        connection.set_trace_callback(None)
    normalized = tuple(statement.upper() for statement in statements)
    assert not any("SUM(" in statement for statement in normalized)
    assert not any("ROW_NUMBER" in statement for statement in normalized)
    assert not any("COUNT(*) FROM CACHE_CONTENTS" in statement for statement in normalized)
    assert any("TEMP.SCAN_CACHE_RUNTIME_ACCOUNTING" in statement for statement in normalized)
    assert any("TEMP.SCAN_CACHE_RUNTIME_LRU" in statement for statement in normalized)
    assert repository.stats()["logical_bytes"] == repository._full_logical_bytes(connection)
    lifecycle.close()


def test_rev21_phase6_cache_runtime_accounting_is_transaction_rollback_safe(
    tmp_path: Path,
) -> None:
    lifecycle, repository = _repository(tmp_path / "profiles")
    connection = lifecycle.connection("cache")
    before_stats = repository.stats()
    before_bytes = int(before_stats["logical_bytes"])
    before_contents = int(before_stats["contents"])
    with pytest.raises(RuntimeError, match="rollback_probe"):
        with lifecycle.transaction("cache") as transaction:
            transaction.execute(
                "INSERT INTO cache_contents(content_sha256,content_size,first_seen_ns,last_seen_ns) "
                "VALUES(?,?,?,?)",
                ("e" * 64, 1, 1, 1),
            )
            runtime_row = transaction.execute(
                "SELECT logical_bytes,content_count FROM temp.scan_cache_runtime_accounting WHERE state_id=1"
            ).fetchone()
            assert runtime_row is not None
            assert int(runtime_row[0]) > before_bytes
            assert int(runtime_row[1]) == before_contents + 1
            raise RuntimeError("rollback_probe")
    after_stats = repository.stats()
    assert int(after_stats["logical_bytes"]) == before_bytes
    assert int(after_stats["contents"]) == before_contents
    assert connection.execute(
        "SELECT 1 FROM cache_contents WHERE content_sha256=?", ("e" * 64,)
    ).fetchone() is None
    assert repository._full_logical_bytes(connection) == before_bytes
    lifecycle.close()
