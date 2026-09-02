import json
from dataclasses import FrozenInstanceError

import pytest

from Virus_Scan.scanners.config.loader import load_payload_policy_result, load_payload_policy_snapshot
from Virus_Scan.scanners.payload_decode import (
    DECODE_LAYER_MAX_CANDIDATES,
    DECODE_LAYER_MAX_TEXT_BYTES,
    DECODE_LAYER_MIN_B64_CHARS,
    DECODE_LAYER_MIN_HEX_CHARS,
    safe_decode_payloads,
)


def test_payload_policy_default_snapshot_is_schema_validated_and_immutable():
    snapshot = load_payload_policy_snapshot()
    assert snapshot.max_candidates == DECODE_LAYER_MAX_CANDIDATES
    assert snapshot.max_text_bytes == DECODE_LAYER_MAX_TEXT_BYTES
    assert snapshot.min_base64_chars == DECODE_LAYER_MIN_B64_CHARS
    assert snapshot.min_hex_chars == DECODE_LAYER_MIN_HEX_CHARS
    with pytest.raises(FrozenInstanceError):
        snapshot.max_candidates = 999  # type: ignore[misc]


def test_invalid_payload_policy_produces_config_failure_evidence(tmp_path):
    invalid = tmp_path / "payload_policy.json"
    invalid.write_text(json.dumps({"schema_version": 1, "max_candidates": 0}), encoding="utf-8")
    result = load_payload_policy_result(invalid)
    assert result.ok is False
    assert result.snapshot is None
    assert result.failure is not None
    assert result.failure.failure_evidence
    evidence = result.failure.failure_evidence[0]
    assert evidence["scanner_name"] == "scanner_config"
    assert evidence["scanner_stage"] == "payload_policy"
    assert evidence["final_json_must_record"] is True


def test_payload_decoder_uses_validated_policy_defaults():
    records = safe_decode_payloads("QUJD")
    assert len(records) <= DECODE_LAYER_MAX_CANDIDATES
