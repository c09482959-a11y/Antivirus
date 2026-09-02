import json

import pytest

from Virus_Scan.scanners.config.contracts import ScannerConfigError
from Virus_Scan.scanners.config.loader import (
    load_engine_policy_result,
    load_engine_policy_snapshot,
    load_filetype_policy_result,
    load_filetype_policy_snapshot,
)
from Virus_Scan.scanners.api.filetype_policy_contracts import (
    BEHAVIOR_MODEL_VERSION,
    ENGINE_SPECIFIC_FILETYPE_BUCKETS,
    GLOBAL_COMMON_FILETYPE_BUCKETS,
    HIGH_RISK_BUCKETS,
)
from Virus_Scan.scanners.unity import detect_unity_runtime_behavior


def test_filetype_policy_loads_as_immutable_snapshot():
    snapshot = load_filetype_policy_snapshot()
    assert snapshot.behavior_model_version == BEHAVIOR_MODEL_VERSION
    assert "os_execution" in snapshot.high_risk_buckets
    assert "asset_image" in snapshot.global_common_filetype_buckets
    assert "unity" in snapshot.engine_specific_filetype_buckets
    assert HIGH_RISK_BUCKETS == snapshot.high_risk_buckets
    assert dict(GLOBAL_COMMON_FILETYPE_BUCKETS) == dict(snapshot.global_common_filetype_buckets)
    assert dict(ENGINE_SPECIFIC_FILETYPE_BUCKETS) == dict(snapshot.engine_specific_filetype_buckets)
    with pytest.raises(TypeError):
        snapshot.global_common_filetype_buckets["new_bucket"] = {}
    with pytest.raises(AttributeError):
        snapshot.high_risk_buckets.add("new_bucket")


def test_filetype_policy_invalid_config_emits_failure_evidence(tmp_path):
    bad = tmp_path / "bad_filetype_policy.json"
    bad.write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
    result = load_filetype_policy_result(bad)
    assert not result.ok
    assert result.failure is not None
    assert result.failure.config_name == "filetype_policy"
    assert result.failure.failure_evidence
    ev = result.failure.failure_evidence[0]
    assert ev["error_category"] == "scanner_config_validation_failure"
    assert ev["error_source"] == "scanner_config.filetype_policy"
    assert ev["final_json_must_record"] is True
    with pytest.raises(ScannerConfigError):
        load_filetype_policy_snapshot(bad)


def test_engine_policy_loads_and_drives_unity_runtime_checks():
    snapshot = load_engine_policy_snapshot()
    assert ("Process.Start", "process_exec") in snapshot.unity_runtime_checks
    assert "Awake" in snapshot.unity_lifecycle_hooks
    tags = detect_unity_runtime_behavior("void Awake() { Process.Start(\"cmd.exe\"); DownloadString(url); }")
    assert "unity_lifecycle" in tags
    assert "process_exec" in tags
    assert "network_download" in tags
    with pytest.raises(AttributeError):
        snapshot.unity_lifecycle_hooks.append("RuntimeInitializeOnLoadMethod")


def test_engine_policy_invalid_config_emits_failure_evidence(tmp_path):
    bad = tmp_path / "bad_engine_policy.json"
    bad.write_text(json.dumps({"schema_version": 1, "unity_lifecycle_hooks": []}), encoding="utf-8")
    result = load_engine_policy_result(bad)
    assert not result.ok
    assert result.failure is not None
    assert result.failure.config_name == "engine_policy"
    ev = result.failure.failure_evidence[0]
    assert ev["error_category"] == "scanner_config_validation_failure"
    assert ev["error_source"] == "scanner_config.engine_policy"
    assert ev["final_json_must_record"] is True
    with pytest.raises(ScannerConfigError):
        load_engine_policy_snapshot(bad)
