from __future__ import annotations

from pathlib import Path

from Virus_Scan.detection.contracts.binary_predicates import (
    strict_fast_file_is_boring_text,
    xor_blob_signal,
)
from Virus_Scan.detection.contracts.calibration_math import sigmoid01
from Virus_Scan.detection.contracts.filetype_context import filetype_validation_context
from Virus_Scan.detection.contracts.path_predicates import binary_ext_for_attack_cap
from Virus_Scan.utils.entropy import strict_fast_entropy


def test_stage944_calibration_sigmoid_is_midpointed_monotonic_and_scale_clamped() -> None:
    low = sigmoid01(0.0)
    midpoint = sigmoid01(2.0)
    high = sigmoid01(10.0)

    assert 0.0 < low < midpoint < high < 1.0
    assert midpoint == 0.5
    assert sigmoid01(2.1, midpoint=2.0, scale=0.0) > midpoint
    assert sigmoid01(1.9, midpoint=2.0, scale=0.0) < midpoint


def test_stage944_filetype_context_uses_engine_specific_policy_before_global_policy() -> None:
    unity_context = filetype_validation_context("unity", "GameAssembly.dll")
    assert unity_context["engine_bucket"] == "unity_managed_code"
    assert unity_context["active_bucket"] == "unity_managed_code"
    assert unity_context["execution_capability"] == "managed"
    assert "credential" in unity_context["high_risk_buckets"]

    rpgm_context = filetype_validation_context("rpgm", "www/js/plugins.js")
    assert rpgm_context["global_bucket"] == "script_common"
    assert rpgm_context["engine_bucket"] == "rpgm_script"
    assert rpgm_context["active_bucket"] == "rpgm_script"
    assert rpgm_context["execution_capability"] == "script"


def test_stage944_filetype_context_marks_non_execution_media_as_high_risk_gated() -> None:
    context = filetype_validation_context("media", "soundtrack.ogg")
    assert context["active_bucket"] == "asset_audio"
    assert context["execution_capability"] == "none"
    assert {"persistence", "credential", "injection"}.issubset(context["high_risk_buckets"])

    unknown = filetype_validation_context("not-a-real-engine", "payload.unknownext")
    assert unknown["engine_bucket"] == "unknown_engine"
    assert unknown["active_bucket"] == "unknown_global"
    assert unknown["execution_capability"] == "unknown"


def test_stage944_binary_predicates_separate_boring_text_from_suspicious_text_and_binary_magic(tmp_path: Path) -> None:
    benign = tmp_path / "notes.txt"
    benign.write_text("ordinary configuration notes\n" * 20, encoding="utf-8")
    is_boring, benign_meta = strict_fast_file_is_boring_text(benign)
    assert is_boring is True
    assert benign_meta["extension"] == ".txt"
    assert benign_meta["nul_ratio"] == 0.0

    suspicious = tmp_path / "script.txt"
    suspicious.write_text("powershell -enc AAAA http://example.invalid\n" * 10, encoding="utf-8")
    suspicious_boring, suspicious_meta = strict_fast_file_is_boring_text(suspicious)
    assert suspicious_boring is False
    assert suspicious_meta["extension"] == ".txt"

    binary_named_text = tmp_path / "archive.txt"
    binary_named_text.write_bytes(b"PK\x03\x04" + b"plain text after magic")
    binary_boring, binary_meta = strict_fast_file_is_boring_text(binary_named_text)
    assert binary_boring is False
    assert binary_meta["extension"] == ".txt"


def test_stage944_entropy_xor_and_binary_extension_contracts_are_fail_closed() -> None:
    assert strict_fast_entropy(None) == 0.0
    assert strict_fast_entropy(b"A" * 1024) < 0.01
    assert strict_fast_entropy(bytes(range(256))) > 7.9

    assert xor_blob_signal(b"short") is False
    assert binary_ext_for_attack_cap("UnityPlayer.DLL") is True
    assert binary_ext_for_attack_cap("game/script.rpy") is False
