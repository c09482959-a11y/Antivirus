"""Phase 7 canonical resource-root and output-plan regressions."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import FrozenInstanceError
import os
from pathlib import Path

import pytest

from Virus_Scan.contracts.path_identity import should_include_scan_path
from Virus_Scan.routing.engine_detect import detect_target_engine_context
from Virus_Scan.routing import engine_target_policy
from Virus_Scan.runtime.engine_hint_runtime import detect_startup_engine_context
from Virus_Scan.runtime import engine_hint_runtime
from Virus_Scan.runtime.resource_paths import (
    RESOURCE_CLASSIFICATION_FINAL_PUBLICATION,
    RESOURCE_CLASSIFICATION_PACKAGE,
    RESOURCE_CLASSIFICATION_ROOT,
    RESOURCE_CLASSIFICATION_RUNTIME_CACHE,
    RESOURCE_CLASSIFICATION_RUNTIME_CONTROL,
    RESOURCE_CLASSIFICATION_RUNTIME_STATE,
    RESOURCE_CLASSIFICATION_SECRET_REFERENCE,
    RESOURCE_CLASSIFICATION_STAGING_OUTPUT,
    RESOURCE_CLASSIFICATION_UNKNOWN,
    build_scan_log_output_plan,
    derive_scan_log_scan_id,
    resource_root_snapshot,
    scan_logs_dir,
    virustotal_dir,
)


@contextmanager
def _base_dir(root: Path):
    previous = os.environ.get("UMIGE_BASE_DIR")
    os.environ["UMIGE_BASE_DIR"] = str(root)
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("UMIGE_BASE_DIR", None)
        else:
            os.environ["UMIGE_BASE_DIR"] = previous


def test_phase7_resource_snapshot_owns_all_four_exact_roots(tmp_path: Path) -> None:
    with _base_dir(tmp_path):
        snapshot = resource_root_snapshot()

        assert snapshot.program_root == tmp_path.resolve().as_posix()
        assert snapshot.yara_root == (tmp_path / "Yara").resolve().as_posix()
        assert snapshot.mitre_root == (tmp_path / "Mitre").resolve().as_posix()
        assert snapshot.mitre_seed_path == (tmp_path / "Mitre/enterprise-attack.json").resolve().as_posix()
        assert snapshot.virustotal_root == (tmp_path / "VirusTotal").resolve().as_posix()
        assert snapshot.scan_logs_root == (tmp_path / "Scan Logs").resolve().as_posix()
        assert len(snapshot.semantic_digest) == 64
        assert virustotal_dir() == tmp_path / "VirusTotal"
        assert scan_logs_dir() == tmp_path / "Scan Logs"
        with pytest.raises(FrozenInstanceError):
            snapshot.scan_logs_root = "mutated"  # type: ignore[misc]


def test_phase7_resource_snapshot_classifies_package_runtime_and_output_paths(
    tmp_path: Path,
) -> None:
    with _base_dir(tmp_path):
        snapshot = resource_root_snapshot()

    assert snapshot.classify(tmp_path / "Yara") == RESOURCE_CLASSIFICATION_ROOT
    assert snapshot.classify(tmp_path / "Yara/yara_config.toml") == RESOURCE_CLASSIFICATION_RUNTIME_CONTROL
    assert snapshot.classify(tmp_path / "Yara/yara.cache/item.yarc") == RESOURCE_CLASSIFICATION_RUNTIME_CACHE
    assert snapshot.classify(tmp_path / "Yara/.umige-yara.lock") == RESOURCE_CLASSIFICATION_RUNTIME_CONTROL
    assert snapshot.classify(tmp_path / "Yara/state/acquisition.json") == RESOURCE_CLASSIFICATION_RUNTIME_STATE
    assert snapshot.classify(tmp_path / "Mitre/enterprise-attack.json") == RESOURCE_CLASSIFICATION_PACKAGE
    assert snapshot.classify(tmp_path / "Mitre/mitre_config.toml") == RESOURCE_CLASSIFICATION_RUNTIME_CONTROL
    assert snapshot.classify(tmp_path / "Mitre/mitre_defaults.toml") == RESOURCE_CLASSIFICATION_RUNTIME_CONTROL
    assert snapshot.classify(tmp_path / "Mitre/state/index.json") == RESOURCE_CLASSIFICATION_RUNTIME_STATE
    assert snapshot.classify(tmp_path / "VirusTotal/virustotal_config.toml") == RESOURCE_CLASSIFICATION_RUNTIME_CONTROL
    assert snapshot.classify(tmp_path / "VirusTotal/.umige-virustotal.lock") == RESOURCE_CLASSIFICATION_RUNTIME_CONTROL
    assert snapshot.classify(tmp_path / "VirusTotal/secret") == RESOURCE_CLASSIFICATION_SECRET_REFERENCE
    assert snapshot.classify(tmp_path / "Scan Logs/README.txt") == RESOURCE_CLASSIFICATION_PACKAGE
    assert snapshot.classify(tmp_path / "Scan Logs/.staging/scan-a/scan_results.json") == RESOURCE_CLASSIFICATION_STAGING_OUTPUT
    assert snapshot.classify(tmp_path / "Scan Logs/runs/scan-a/scan_results.json") == RESOURCE_CLASSIFICATION_FINAL_PUBLICATION
    assert snapshot.classify(tmp_path / "Scan Logs/latest.json") == RESOURCE_CLASSIFICATION_FINAL_PUBLICATION
    assert snapshot.classify(tmp_path / "outside.txt") == RESOURCE_CLASSIFICATION_UNKNOWN


def test_phase7_scan_log_output_plan_is_exact_deterministic_and_immutable(
    tmp_path: Path,
) -> None:
    generation = "a" * 64
    scan_id = derive_scan_log_scan_id(session_generation=generation, started_ns=123)

    with _base_dir(tmp_path):
        first = build_scan_log_output_plan(scan_id=scan_id)
        second = build_scan_log_output_plan(scan_id=scan_id)

    assert first == second
    assert first.semantic_digest == second.semantic_digest
    assert first.scan_log_root == (tmp_path / "Scan Logs").resolve().as_posix()
    assert first.staging_path == (tmp_path / "Scan Logs/.staging" / scan_id).resolve().as_posix()
    assert first.run_path == (tmp_path / "Scan Logs/runs" / scan_id).resolve().as_posix()
    assert first.latest_path == (tmp_path / "Scan Logs/latest.json").resolve().as_posix()
    assert first.report_path("scan_results.json") == Path(first.run_path) / "scan_results.json"
    assert first.staging_report_path("scan_results.json") == Path(first.staging_path) / "scan_results.json"
    assert first.to_record()["report_paths"]["virustotal_results.json"].endswith(
        "/virustotal_results.json"
    )
    with pytest.raises(FrozenInstanceError):
        first.scan_id = "mutated"  # type: ignore[misc]
    with pytest.raises(KeyError, match="scan_log_report_filename_unknown"):
        first.report_path("unknown.json")


def test_phase7_scan_id_and_output_plan_reject_ambiguous_identity(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="scan_log_session_generation_invalid"):
        derive_scan_log_scan_id(session_generation="short", started_ns=1)
    with pytest.raises(ValueError, match="scan_log_started_ns_invalid"):
        derive_scan_log_scan_id(session_generation="a" * 64, started_ns=-1)
    with pytest.raises(ValueError, match="scan_log_scan_id_invalid"):
        build_scan_log_output_plan(scan_id="../escape", root=tmp_path / "Scan Logs")
    with pytest.raises(ValueError, match="scan_log_root_invalid"):
        build_scan_log_output_plan(scan_id="scan-a", root=tmp_path / "Other")


def test_phase7_scan_policy_excludes_all_canonical_roots_without_hiding_external_target(
    tmp_path: Path,
) -> None:
    for name in ("Yara", "Mitre", "VirusTotal", "Scan Logs"):
        generated = tmp_path / name / "owned.txt"
        generated.parent.mkdir(parents=True, exist_ok=True)
        generated.write_text("owned", encoding="utf-8")
        assert should_include_scan_path(generated, scan_root=tmp_path) is False

    external_root = tmp_path / "host" / "Scan Logs"
    external_target = external_root / "user-selected" / "sample.bin"
    external_target.parent.mkdir(parents=True)
    external_target.write_bytes(b"sample")
    assert should_include_scan_path(external_target, scan_root=external_root) is True


def test_phase7_engine_discovery_uses_canonical_scan_path_policy_for_owned_roots(
    tmp_path: Path,
) -> None:
    for name in ("Yara", "Mitre", "VirusTotal", "Scan Logs"):
        owned_root = tmp_path / name
        owned_root.mkdir(parents=True, exist_ok=True)
        (owned_root / "UnityPlayer.dll").write_bytes(b"MZ" + b"unity" * 16)

    startup = detect_startup_engine_context(tmp_path, max_files=100)
    target = detect_target_engine_context(tmp_path, max_files=100)

    assert startup["unity"] == 0.0
    assert startup["unknown"] == 1.0
    assert target["unity"] == 0.0
    assert target["unknown"] > 0.99


def test_phase7_explicit_external_scan_logs_target_is_not_hidden_by_root_name(
    tmp_path: Path,
) -> None:
    external_root = tmp_path / "host" / "Scan Logs"
    external_root.mkdir(parents=True)
    (external_root / "UnityPlayer.dll").write_bytes(b"MZ" + b"unity" * 16)

    assert detect_startup_engine_context(external_root, max_files=100)["unity"] > 0.8
    assert detect_target_engine_context(external_root, max_files=100)["unity"] > 0.8


def test_phase7_no_engine_layer_owns_a_parallel_scan_artifact_registry() -> None:
    assert not hasattr(engine_hint_runtime, "_EXCLUDED_STARTUP_ARTIFACT_DIRS")
    assert not hasattr(engine_target_policy, "EXCLUDED_SCAN_ARTIFACT_DIRS")


def test_phase7_generated_control_contract_is_exact_and_distinct_from_payloads(tmp_path: Path) -> None:
    with _base_dir(tmp_path):
        snapshot = resource_root_snapshot()
    observed = {
        (root_name, Path(path).name)
        for root_name, path in snapshot.generated_control_resources()
    }
    assert observed == {
        ("Yara", "README.md"),
        ("Yara", "yara_defaults.toml"),
        ("Yara", "yara_config.toml"),
        ("Yara", "yara_config.schema.json"),
        ("Mitre", "README.md"),
        ("Mitre", "mitre_defaults.toml"),
        ("Mitre", "mitre_config.toml"),
        ("Mitre", "mitre_config.schema.json"),
        ("VirusTotal", "README.md"),
        ("VirusTotal", "virustotal_defaults.toml"),
        ("VirusTotal", "virustotal_config.toml"),
        ("VirusTotal", "virustotal_config.schema.json"),
    }
    immutable = {
        (root_name, Path(path).name)
        for root_name, path in snapshot.immutable_package_resources()
    }
    assert ("Mitre", "enterprise-attack.json") in immutable
    assert not observed.intersection(immutable)
