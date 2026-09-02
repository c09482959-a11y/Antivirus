import json
from dataclasses import FrozenInstanceError

import pytest

from Virus_Scan.scanners.config.loader import (
    load_pickle_policy_result,
    load_pickle_policy_snapshot,
    load_raw_chunk_policy_result,
    load_raw_chunk_policy_snapshot,
    load_text_policy_result,
    load_text_policy_snapshot,
)
from Virus_Scan.scanners import raw_chunk_core, text
from Virus_Scan.scanners.pickle import embedded_payloads, escalation, escalation_context


def test_pickle_policy_default_snapshot_is_validated_immutable_and_used_by_scanner():
    snapshot = load_pickle_policy_snapshot()
    assert snapshot.fast_escalation_max_bytes == escalation.PICKLE_FAST_ESCALATION_MAX_BYTES
    assert frozenset(snapshot.renpy_extensions) == escalation.PICKLE_FAST_RENPY_EXTS
    assert snapshot.decode_max_file_bytes == embedded_payloads.PICKLE_DECODE_MAX_FILE_BYTES
    assert snapshot.fast_dangerous_text == escalation_context.PICKLE_FAST_DANGEROUS_TEXT
    with pytest.raises(FrozenInstanceError):
        snapshot.decode_max_file_bytes = 1  # type: ignore[misc]


def test_invalid_pickle_policy_produces_scanner_config_failure_evidence(tmp_path):
    invalid = tmp_path / "pickle_policy.json"
    invalid.write_text(json.dumps({"schema_version": 1, "fast_escalation_max_bytes": 0}), encoding="utf-8")
    result = load_pickle_policy_result(invalid)
    assert result.ok is False
    assert result.snapshot is None
    assert result.failure is not None
    assert result.failure.failure_evidence
    evidence = result.failure.failure_evidence[0]
    assert evidence["scanner_name"] == "scanner_config"
    assert evidence["scanner_stage"] == "pickle_policy"
    assert evidence["final_json_must_record"] is True


def test_raw_chunk_policy_default_snapshot_is_validated_immutable_and_used_by_scanner():
    snapshot = load_raw_chunk_policy_snapshot()
    assert snapshot.context_anchors == raw_chunk_core.DEFAULT_GLOBAL_RAW_CONTEXT_ANCHORS
    assert snapshot.decode_anchors == raw_chunk_core.DEFAULT_GLOBAL_RAW_DECODE_ANCHORS
    assert raw_chunk_core.should_context_scan("powershell encodedcommand") is True
    with pytest.raises(FrozenInstanceError):
        snapshot.context_anchors = ()  # type: ignore[misc]


def test_invalid_raw_chunk_policy_produces_scanner_config_failure_evidence(tmp_path):
    invalid = tmp_path / "raw_chunk_core.json"
    invalid.write_text(json.dumps({"schema_version": 1, "context_anchors": []}), encoding="utf-8")
    result = load_raw_chunk_policy_result(invalid)
    assert result.ok is False
    assert result.snapshot is None
    evidence = result.failure.failure_evidence[0]  # type: ignore[union-attr]
    assert evidence["scanner_name"] == "scanner_config"
    assert evidence["scanner_stage"] == "raw_chunk_policy"
    assert evidence["final_json_must_record"] is True


def test_text_policy_default_snapshot_is_validated_immutable_and_used_by_scanner():
    snapshot = load_text_policy_snapshot()
    assert snapshot.runtime_strong_attack_context == text._RUNTIME_STRONG_ATTACK_CONTEXT
    assert snapshot.correlation_group_keywords == text.CORRELATION_GROUP_KEYWORDS
    assert snapshot.vector_cluster_max_bonus == text.VECTOR_CLUSTER_MAX_BONUS
    assert snapshot.combined_context_max_bonus == text.COMBINED_CONTEXT_MAX_BONUS
    with pytest.raises(FrozenInstanceError):
        snapshot.vector_cluster_max_bonus = 99.0  # type: ignore[misc]


def test_invalid_text_policy_produces_scanner_config_failure_evidence(tmp_path):
    invalid = tmp_path / "text_policy.json"
    invalid.write_text(json.dumps({"schema_version": 1, "runtime_strong_attack_context": []}), encoding="utf-8")
    result = load_text_policy_result(invalid)
    assert result.ok is False
    assert result.snapshot is None
    evidence = result.failure.failure_evidence[0]  # type: ignore[union-attr]
    assert evidence["scanner_name"] == "scanner_config"
    assert evidence["scanner_stage"] == "text_policy"
    assert evidence["final_json_must_record"] is True
