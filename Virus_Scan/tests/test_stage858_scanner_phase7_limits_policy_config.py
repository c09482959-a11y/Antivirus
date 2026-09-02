from Virus_Scan.detection.tags.evidence_generation import finalize_tag_evidence_generation
import json

import pytest

from Virus_Scan.scanners.config.loader import (
    load_archive_policy_snapshot,
    load_scanner_limits_policy_result,
    load_scanner_limits_policy_snapshot,
)
from Virus_Scan.scanners import image_limits, raw_chunk_core, raw_queue_scan_result, strings, text
from Virus_Scan.scanners.payload_decode import DECODE_LAYER_MAX_CANDIDATES as PAYLOAD_MAX_CANDIDATES
from Virus_Scan.scanners.payload_decode import DECODE_LAYER_MAX_TEXT_BYTES as PAYLOAD_MAX_TEXT_BYTES
from Virus_Scan.scanners.pickle.rpa_views import RPA_INDEX_MAX_BYTES, RPA_MEMBER_MAX_BYTES, RPA_MEMBER_MAX_COUNT
from Virus_Scan.scanners.raw_queue_scan_result import RawQueueScanResultDependencies
from Virus_Scan.scanners.renpy import _rpa_archive_scan_caps


def _raw_queue_test_list(value: object) -> list[object]:
    if isinstance(value, list):
        return list(value)
    if isinstance(value, tuple):
        return list(value)
    return []


def test_scanner_limits_policy_snapshot_is_validated_and_immutable():
    snapshot = load_scanner_limits_policy_snapshot()
    assert snapshot.schema == "scanner_limits_policy.v1"
    assert snapshot.image_stego_sample_pixels == 262144
    assert snapshot.strings_intrastage_chunk_overlap == 4096
    assert snapshot.raw_queue_strings_blob_max_chars == 262144
    with pytest.raises(AttributeError):
        setattr(snapshot, "raw_queue_strings_blob_max_chars", 1)


def test_invalid_scanner_limits_policy_returns_visible_failure_evidence(tmp_path):
    bad = tmp_path / "scanner_limits_policy.json"
    bad.write_text(json.dumps({"schema_version": 1, "image_stego_max_file_bytes": 0}), encoding="utf-8")
    result = load_scanner_limits_policy_result(bad)
    assert not result.ok
    assert result.snapshot is None
    assert result.failure is not None
    assert result.failure.config_name == "scanner_limits_policy"
    assert result.failure_evidence
    assert result.failure_evidence[0]["error_category"] == "scanner_config_validation_failure"


def test_image_string_raw_limits_are_config_snapshot_owned():
    limits = load_scanner_limits_policy_snapshot()
    assert image_limits.IMAGE_STEGO_MAX_FILE_BYTES == limits.image_stego_max_file_bytes
    assert image_limits.IMAGE_STEGO_MAX_PIXELS == limits.image_stego_max_pixels
    assert image_limits.IMAGE_STEGO_SAMPLE_PIXELS == limits.image_stego_sample_pixels
    assert image_limits.deep_scan_image_enrichment_limit(escalated=False) == limits.image_enrichment_fast_bytes
    assert strings.INTRASTAGE_MIN_TEXT_CHARS == limits.strings_intrastage_min_text_chars
    assert strings.INTRASTAGE_CHUNK_CHARS == limits.strings_intrastage_chunk_chars
    assert strings.INTRASTAGE_MAX_CHUNKS == limits.strings_intrastage_max_chunks
    assert text.DECODE_LAYER_MAX_CANDIDATES == text._PAYLOAD_POLICY.max_candidates
    assert text.DECODE_LAYER_MAX_TEXT_BYTES == text._PAYLOAD_POLICY.max_text_bytes
    assert text.BROAD_UNVALIDATED_TAGS == text._TEXT_POLICY.broad_unvalidated_tags
    assert text.PASSIVE_TEXTUAL_CATEGORIES == text._TEXT_POLICY.passive_textual_categories
    assert text.GAME_ENGINE_CONTEXT_TAGS == text._TEXT_POLICY.game_engine_context_tags
    assert raw_chunk_core._SCANNER_LIMITS_POLICY.raw_chunk_default_read_size == limits.raw_chunk_default_read_size


def test_raw_queue_strings_blob_cap_uses_scanner_limits_policy():
    limits = load_scanner_limits_policy_snapshot()
    deps = RawQueueScanResultDependencies(
        ordered_unique_tags=_raw_queue_test_list,
        finalize_tag_evidence_generation=finalize_tag_evidence_generation,
        apply_integrity_tags=lambda tags, *_args, **_kwargs: _raw_queue_test_list(tags),
        normalize_tags=_raw_queue_test_list,
        staged_enrichment_score=lambda *_args, **_kwargs: (0.0, []),
        scanner_degraded_tags=_raw_queue_test_list,
        mark_raw_integrity_failure=lambda _p, integrity, **_kwargs: integrity,
        remember_scan_evidence=lambda *_args, **_kwargs: None,
        normalize_yara_hits=_raw_queue_test_list,
        set_scan_integrity=lambda *_args, **_kwargs: None,
    )
    result = raw_queue_scan_result.build_global_raw_scan_result(
        path="sample.txt",
        file_id="id",
        accum={"expected": 1, "completed": 1, "strings_parts": ["A" * (limits.raw_queue_strings_blob_max_chars + 64)]},
        identity={"tags": []},
        effective_stage="text",
        deps=deps,
    )
    strings_blob = result["strings_blob"]
    assert isinstance(strings_blob, str)
    assert len(strings_blob) == limits.raw_queue_strings_blob_max_chars


def test_pickle_rpa_and_payload_decode_limits_use_policy_snapshots():
    limits = load_scanner_limits_policy_snapshot()
    archive_policy = load_archive_policy_snapshot()
    assert PAYLOAD_MAX_CANDIDATES == text._PAYLOAD_POLICY.max_candidates
    assert PAYLOAD_MAX_TEXT_BYTES == text._PAYLOAD_POLICY.max_text_bytes
    assert RPA_INDEX_MAX_BYTES == archive_policy.rpa_index_max_bytes
    assert RPA_MEMBER_MAX_BYTES == archive_policy.rpa_member_max_bytes
    assert RPA_MEMBER_MAX_COUNT == archive_policy.rpa_member_max_count
    assert _rpa_archive_scan_caps() == {
        "max_depth": archive_policy.rpa_zip_max_depth,
        "max_members": archive_policy.rpa_zip_max_members,
        "max_member_size": archive_policy.rpa_zip_max_member_size,
    }
    assert limits.raw_chunk_mz_probe_bytes == 4096
