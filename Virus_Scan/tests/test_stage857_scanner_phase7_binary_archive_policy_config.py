import json

import pytest

from Virus_Scan.scanners.config.contracts import ScannerConfigError
from Virus_Scan.scanners.config.loader import (
    load_archive_policy_result,
    load_archive_policy_snapshot,
    load_binary_policy_result,
    load_binary_policy_snapshot,
)
from Virus_Scan.scanners.dotnet_identity import (
    DOTNET_BEHAVIOR_MARKERS,
    DOTNET_EXTENSION_MISMATCH_EXTENSIONS,
    DOTNET_EXTENSIONS,
    dotnet_behavior_tags,
    dotnet_extension_tags,
    dotnet_metadata_present,
)
from Virus_Scan.scanners.entropy import detect_packer_entropy_anomaly
from Virus_Scan.scanners.archives import rarity_multiplier_for_probability
from Virus_Scan.scanners.il_pipeline import analyze_il_pipeline, extract_il_patterns


def test_binary_policy_snapshot_is_validated_and_immutable():
    snapshot = load_binary_policy_snapshot()
    assert snapshot.schema == "binary_policy.v1"
    assert ".dll" in snapshot.dotnet_extensions
    assert "upx" in snapshot.entropy_packer_markers
    assert ("process_exec", 0.25) in tuple(snapshot.il_behavior_tag_weights.items())
    with pytest.raises(AttributeError):
        snapshot.entropy_high_threshold = 1.0
    with pytest.raises((AttributeError, TypeError)):
        snapshot.dotnet_extensions.add(".mutable")
    with pytest.raises(TypeError):
        snapshot.il_behavior_tag_weights["mutable"] = 1.0


def test_invalid_binary_policy_returns_visible_failure_evidence(tmp_path):
    bad = tmp_path / "binary_policy.json"
    bad.write_text(json.dumps({"schema_version": 1, "entropy_read_max_bytes": 0}), encoding="utf-8")
    result = load_binary_policy_result(bad)
    assert not result.ok
    assert result.snapshot is None
    assert result.failure is not None
    assert result.failure.config_name == "binary_policy"
    assert result.failure_evidence
    assert result.failure_evidence[0]["error_category"] == "scanner_config_validation_failure"


def test_archive_policy_snapshot_controls_archive_rarity_thresholds():
    snapshot = load_archive_policy_snapshot()
    assert snapshot.schema == "archive_policy.v1"
    assert snapshot.default_max_depth == 2
    assert snapshot.rpa_zip_max_members == 64
    assert rarity_multiplier_for_probability(0.00001, risk=8.0, bucket="os_execution") == snapshot.rarity_high_risk_multiplier
    assert rarity_multiplier_for_probability(0.5, risk=0.0, bucket="other_behavior") == snapshot.rarity_default_multiplier


def test_invalid_archive_policy_returns_visible_failure_evidence(tmp_path):
    bad = tmp_path / "archive_policy.json"
    bad.write_text(json.dumps({"schema_version": 1, "default_max_depth": -1}), encoding="utf-8")
    result = load_archive_policy_result(bad)
    assert not result.ok
    assert result.failure is not None
    assert result.failure.config_name == "archive_policy"
    assert result.failure_evidence
    assert result.failure_evidence[0]["error_source"] == "scanner_config.archive_policy"


def test_binary_policy_drives_dotnet_entropy_and_il_behavior(tmp_path):
    assert ".bytes" in DOTNET_EXTENSIONS
    assert ".bytes" in DOTNET_EXTENSION_MISMATCH_EXTENSIONS
    assert dotnet_extension_tags(".bytes") == ["extension_mismatch", "binary_failover_dotnet_metadata"]
    assert dotnet_metadata_present("MScoree.dll #Strings Assembly.Load")
    assert "assembly_load" in dotnet_behavior_tags("Assembly.Load WebClient")
    assert DOTNET_BEHAVIOR_MARKERS

    packed = tmp_path / "packed.bin"
    packed.write_bytes(b"UPX" + bytes(range(256)) * 1024)
    result = detect_packer_entropy_anomaly(packed)
    assert "packer_marker" in result["tags"]

    ops = extract_il_patterns("ldstr call System.Diagnostics.Process Start(")
    assert "CALL" in ops and "LDSTR" in ops and "PROCESS" in ops
    il_result = analyze_il_pipeline("sample.dll", ["process_exec"], strings_blob="ldstr call System.Diagnostics.Process Start(")
    assert il_result["il_score"] > 0
