from __future__ import annotations

from pathlib import Path

from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture
from Virus_Scan.contracts.scan_cache_fingerprint import (
    SCAN_CACHE_RESULT_SCHEMA_VERSION,
    scan_cache_options_fingerprint,
    scan_cache_options_payload,
)
import Virus_Scan.core.cache as core_cache
from Virus_Scan.core.cache import pre_scan_cache_lookup
import Virus_Scan.reporting.output as reporting_output
import Virus_Scan.reporting.result_schema as result_schema
from Virus_Scan.storage import scan_cache_repository, sqlite_lifecycle
from Virus_Scan.tests.support.scan_cache_fixtures import (
    disabled_scan_cache_identity,
    unavailable_scan_cache_identity,
    verified_scan_cache_identity,
)


def test_stage975_scan_cache_fingerprint_has_one_canonical_contract() -> None:
    assert not hasattr(core_cache, "scan_cache_options_fingerprint")
    assert not hasattr(result_schema, "scan_cache_options_fingerprint")
    assert len(scan_cache_options_fingerprint(disabled_scan_cache_identity())) == 64


def test_stage975_scan_cache_payload_binds_exact_yara_attack_and_result_identity() -> None:
    identity = verified_scan_cache_identity()
    payload = scan_cache_options_payload(identity)
    assert payload["schema"] == 3
    assert payload["profile_schema"] == 2
    assert payload["result_schema"] == SCAN_CACHE_RESULT_SCHEMA_VERSION
    assert payload["execution_identity"] == identity.to_record()
    assert payload["execution_identity"]["yara_state"] == "verified"
    assert payload["execution_identity"]["yara_package_kind"] == "core"
    assert payload["execution_identity"]["attack_state"] == "available"


def test_stage975_cache_fingerprint_changes_for_every_semantic_identity_axis() -> None:
    baseline = verified_scan_cache_identity()
    variants = (
        verified_scan_cache_identity(package_kind="extended"),
        verified_scan_cache_identity(source_seed="9"),
        verified_scan_cache_identity(compiled_seed="a"),
        verified_scan_cache_identity(catalog_seed="b"),
        verified_scan_cache_identity(alignment_seed="c"),
        verified_scan_cache_identity(implementation_seed="d"),
        verified_scan_cache_identity(policy_seed="e"),
        verified_scan_cache_identity(repository_seed="f"),
        verified_scan_cache_identity(dataset_seed="0"),
        disabled_scan_cache_identity(),
    )
    baseline_digest = scan_cache_options_fingerprint(baseline)
    assert len({baseline_digest, *(scan_cache_options_fingerprint(item) for item in variants)}) == len(variants) + 1


def test_stage975_unavailable_dependency_is_explicitly_cache_ineligible() -> None:
    identity = unavailable_scan_cache_identity()
    assert identity.yara_state == "unavailable"
    assert identity.attack_state == "unavailable"
    assert identity.cache_eligible is False


def test_stage975_reporting_output_no_longer_owns_scan_cache_fingerprint() -> None:
    assert not hasattr(reporting_output, "_scan_cache_options_fingerprint")


def test_stage975_lookup_reuses_only_exact_execution_identity(tmp_path: Path) -> None:
    sample = tmp_path / "payload.bin"
    sample.write_bytes(b"cache-identity-payload")
    identity = verified_scan_cache_identity()
    changed = verified_scan_cache_identity(alignment_seed="9")
    snapshot = artifact_read_snapshot_fixture(sample)
    sha256 = snapshot.content_sha256
    result = {
        "file": str(sample),
        "path": str(sample),
        "classification": "benign_clean",
        "score": 0.0,
        "tags": ["binary_file"],
        "scan_integrity": {"allow_learning": True},
        "learn_eligible": True,
    }
    repository = scan_cache_repository()
    repository.configure(tmp_path / "profiles", enabled=True)
    try:
        repository.put_result(
            content_sha256=sha256,
            content_size=sample.stat().st_size,
            canonical_path=str(sample.resolve()),
            file_name=sample.name,
            execution_identity=identity,
            result=result,
        )
        exact, exact_sha = pre_scan_cache_lookup(snapshot, execution_identity=identity)
        stale, stale_sha = pre_scan_cache_lookup(snapshot, execution_identity=changed)
        assert exact is not None
        assert exact_sha == sha256
        assert stale is None
        assert stale_sha == sha256
    finally:
        repository.configure(tmp_path / "disabled", enabled=False)
        sqlite_lifecycle().close()


def test_stage975_unavailable_identity_rejects_lookup_before_file_or_hash_access(tmp_path: Path) -> None:
    touched = {"snapshot": 0}
    result = pre_scan_cache_lookup(
        object(), execution_identity=unavailable_scan_cache_identity(),
    )
    assert result == (None, "")
    assert touched == {"snapshot": 0}
