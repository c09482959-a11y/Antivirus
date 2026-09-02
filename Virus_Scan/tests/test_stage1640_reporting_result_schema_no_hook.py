"""Stage 1640 reporting result-schema no-hook boundary regressions."""
from __future__ import annotations
from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture
from Virus_Scan.contracts.artifact_read_snapshot import attach_artifact_read_record

from Virus_Scan.tests.support.scan_cache_fixtures import disabled_scan_cache_identity
from Virus_Scan.reporting.result_schema import (
    _umige_passive_fast_cache_without_full_sha,
    _umige_result_is_retryable_file_failure,
)
from Virus_Scan.storage.scan_cache_result_writer.scan_cache_result_writer import ScanCacheResultWriter


class HostileReportingValue:
    touched = 0

    def __str__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned __str__ must not execute")

    def __repr__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned __repr__ must not execute")

    def __bool__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned truthiness must not execute")


class HostileReportingTag:
    touched = 0

    def __str__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned tag __str__ must not execute")

    def __repr__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned tag __repr__ must not execute")

    def lower(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned tag lower must not execute")


class HostileMapping(dict):
    touched = 0

    def get(self, key, default=None):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned mapping get must not execute")


def test_stage1640_passive_fast_cache_tag_gate_rejects_hostile_tags_without_stringifying() -> None:
    HostileReportingTag.touched = 0

    result = {"tags": [HostileReportingTag(), "media_asset"]}

    assert _umige_passive_fast_cache_without_full_sha(result) is False
    assert HostileReportingTag.touched == 0


def test_stage1640_store_scan_cache_result_rejects_hostile_classification_before_normalization(tmp_path) -> None:
    HostileReportingValue.touched = 0
    sample = tmp_path / "game.exe"
    sample.write_bytes(b"payload")

    result = {
        "file": str(sample),
        "path": str(sample),
        "classification": HostileReportingValue(),
        "tags": ["asset_fast_triage_clean"],
        "score": 1.0,
    }

    attach_artifact_read_record(result, artifact_read_snapshot_fixture(sample))
    assert ScanCacheResultWriter(disabled_scan_cache_identity())(result) is False
    assert HostileReportingValue.touched == 0


def test_stage1640_retryable_failure_rejects_hostile_error_text_without_stringifying() -> None:
    HostileReportingValue.touched = 0

    result = {"class": "benign_clean", "error": HostileReportingValue()}

    assert _umige_result_is_retryable_file_failure(result) is True
    assert HostileReportingValue.touched == 0


def test_stage1640_retryable_failure_does_not_use_caller_owned_mapping_get() -> None:
    HostileMapping.touched = 0

    assert _umige_result_is_retryable_file_failure(HostileMapping({"error": "timeout"})) is True
    assert HostileMapping.touched == 0
