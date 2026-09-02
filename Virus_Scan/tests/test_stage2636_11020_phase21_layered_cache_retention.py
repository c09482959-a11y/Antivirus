"""Phase 21 layered SQLite cache retention and dependency-reuse gates."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from Virus_Scan.storage import ScanCacheRepository, SQLiteLifecycleOwner
from Virus_Scan.tests.support.scan_cache_fixtures import verified_scan_cache_identity
from Virus_Scan.tests.test_stage2636_11020_phase11_static_program_analysis_contract import _analysis


def _repository(root: Path) -> tuple[SQLiteLifecycleOwner, ScanCacheRepository]:
    lifecycle = SQLiteLifecycleOwner()
    repository = ScanCacheRepository(lifecycle)
    repository.configure(root, enabled=True)
    repository.configure_retention(
        max_contents=16,
        max_aliases_per_content=4,
        max_results_per_content=2,
        max_total_bytes=10_000_000,
        max_age_seconds=3600,
    )
    return lifecycle, repository


def test_phase21_every_layer_is_bounded_per_content(tmp_path: Path) -> None:
    lifecycle, repository = _repository(tmp_path / "profiles")
    analysis = _analysis()
    record_json = json.dumps(
        analysis.to_record(), sort_keys=True, separators=(",", ":"), allow_nan=False,
    )
    record_sha = hashlib.sha256(record_json.encode("utf-8")).hexdigest()
    try:
        for index in range(5):
            digest = f"{index + 1:064x}"
            assert repository.put_static_analysis(
                content_sha256=analysis.content_sha256,
                content_size=analysis.content_size,
                analysis_dependency_digest=digest,
                analysis=analysis,
            ) is True
        connection = lifecycle.connection("cache")
        for table, digest_column, payload_column, sha_column in (
            ("cache_parse_results", "parser_digest", "result_json", "result_sha256"),
            (
                "cache_scanner_observations",
                "scanner_digest",
                "observations_json",
                "observations_sha256",
            ),
        ):
            for index in range(5):
                digest = f"{index + 11:064x}"
                connection.execute(
                    f"INSERT INTO {table}(content_sha256,{digest_column},{payload_column},{sha_column},"
                    "status,cached_ns,last_access_ns) VALUES(?,?,?,?,?,?,?)",
                    (
                        analysis.content_sha256,
                        digest,
                        record_json,
                        record_sha,
                        "complete",
                        index + 1,
                        index + 1,
                    ),
                )
        repository.maintenance(force=False)
        for table in (
            "cache_semantic_results",
            "cache_parse_results",
            "cache_static_operations",
            "cache_scanner_observations",
        ):
            count = connection.execute(
                f"SELECT COUNT(*) FROM {table} WHERE content_sha256=?",
                (analysis.content_sha256,),
            ).fetchone()[0]
            assert count <= 2
        retained_static = tuple(
            row[0]
            for row in connection.execute(
                "SELECT analysis_digest FROM cache_static_operations WHERE content_sha256=? "
                "ORDER BY analysis_digest",
                (analysis.content_sha256,),
            ).fetchall()
        )
        assert retained_static == (f"{4:064x}", f"{5:064x}")
    finally:
        lifecycle.close()


def test_phase21_static_layer_reuses_across_yara_drift_while_final_result_misses(
    tmp_path: Path,
) -> None:
    lifecycle, repository = _repository(tmp_path / "profiles")
    analysis = _analysis()
    dependency = "a" * 64
    core = verified_scan_cache_identity(package_kind="core")
    extended = verified_scan_cache_identity(
        package_kind="extended", source_seed="9", compiled_seed="a", catalog_seed="b",
    )
    target = tmp_path / "sample.py"
    try:
        assert repository.put_static_analysis(
            content_sha256=analysis.content_sha256,
            content_size=analysis.content_size,
            analysis_dependency_digest=dependency,
            analysis=analysis,
        ) is True
        assert repository.put_result(
            content_sha256=analysis.content_sha256,
            content_size=analysis.content_size,
            canonical_path=str(target),
            file_name=target.name,
            execution_identity=core,
            result={"classification": "benign_clean", "tags": []},
        ) is True
        assert repository.get_result(
            content_sha256=analysis.content_sha256,
            execution_identity=extended,
            canonical_path=str(target),
            file_name=target.name,
            content_size=analysis.content_size,
        ) is None
        static_hit = repository.get_static_analysis(
            content_sha256=analysis.content_sha256,
            analysis_dependency_digest=dependency,
        )
        assert static_hit is not None
        assert static_hit.analysis.to_record() == analysis.to_record()
    finally:
        lifecycle.close()


def test_phase21_failed_and_truncated_static_analysis_are_never_reused(
    tmp_path: Path,
) -> None:
    from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
    from Virus_Scan.scanners.static_program_analysis import (
        PYTHON_RENPY_MAX_SOURCE_BYTES,
        analyze_python_renpy_snapshot,
    )
    from Virus_Scan.storage import scan_cache_repository, sqlite_lifecycle
    import os

    previous = os.environ.get("UMIGE_BASE_DIR")
    runtime_root = tmp_path / "runtime"
    os.environ["UMIGE_BASE_DIR"] = str(runtime_root)
    sqlite_lifecycle().close()
    try:
        scan_cache_repository().configure(runtime_root / "profiles", enabled=True)
        malformed = tmp_path / "malformed.py"
        malformed.write_text("broken(\n", encoding="utf-8")
        malformed_snapshot = build_artifact_read_snapshot(malformed)
        first_failed = analyze_python_renpy_snapshot(malformed_snapshot)
        second_failed = analyze_python_renpy_snapshot(malformed_snapshot)
        assert first_failed.analysis.parser_status == "failed"
        assert second_failed.analysis.parser_status == "failed"
        assert (first_failed.cache_source, second_failed.cache_source) == ("computed", "computed")

        large = tmp_path / "large.py"
        large.write_bytes(b"#" * (PYTHON_RENPY_MAX_SOURCE_BYTES + 1))
        large_snapshot = build_artifact_read_snapshot(large)
        first_truncated = analyze_python_renpy_snapshot(large_snapshot)
        second_truncated = analyze_python_renpy_snapshot(large_snapshot)
        assert first_truncated.analysis.parser_status == "truncated"
        assert second_truncated.analysis.parser_status == "truncated"
        assert (first_truncated.cache_source, second_truncated.cache_source) == ("computed", "computed")
        assert scan_cache_repository().stats()["static_analyses"] == 0
    finally:
        scan_cache_repository().configure(runtime_root / "profiles", enabled=False)
        sqlite_lifecycle().close()
        if previous is None:
            os.environ.pop("UMIGE_BASE_DIR", None)
        else:
            os.environ["UMIGE_BASE_DIR"] = previous
