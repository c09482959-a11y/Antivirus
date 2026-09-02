from __future__ import annotations

import copy
import inspect
import os
from pathlib import Path

from Virus_Scan.contracts.runtime_platform_identity import runtime_platform_identity
from Virus_Scan.contracts.scan_session_snapshot import (
    SCAN_SESSION_SNAPSHOT_SCHEMA_VERSION,
    scan_session_generation_id,
    scan_session_snapshot_from_record,
)
from Virus_Scan.orchestration.scan_session import (
    build_scan_session_snapshot,
    validate_scan_session_runtime,
)
from Virus_Scan.scanners.static_program_analysis.javascript_typescript_frontend import (
    javascript_typescript_parser_resource_state,
)
from Virus_Scan.scanners.static_program_analysis.native_capstone_runtime import (
    native_decoder_resource_state,
)
from Virus_Scan.storage import sqlite_lifecycle
from Virus_Scan.scheduler.workers import inmemory_file_scan_steps
from Virus_Scan.scheduler.workers import inmemory_worker_bootstrap


def _build(tmp_path: Path):
    previous = os.environ.get("UMIGE_BASE_DIR")
    os.environ["UMIGE_BASE_DIR"] = str(tmp_path / "runtime")
    try:
        return build_scan_session_snapshot(
            compiled_rules=None,
            yara_enabled=False,
            scan_mode="serial",
            worker_count=1,
        )
    finally:
        if previous is None:
            os.environ.pop("UMIGE_BASE_DIR", None)
        else:
            os.environ["UMIGE_BASE_DIR"] = previous


def test_phase12_session_freezes_platform_and_packaged_runtime_identities(tmp_path: Path) -> None:
    previous = os.environ.get("UMIGE_BASE_DIR")
    os.environ["UMIGE_BASE_DIR"] = str(tmp_path / "runtime")
    try:
        snapshot = build_scan_session_snapshot(
            compiled_rules=None,
            yara_enabled=False,
            scan_mode="serial",
            worker_count=1,
        )
        platform_identity = runtime_platform_identity()
        assert snapshot.schema_version == SCAN_SESSION_SNAPSHOT_SCHEMA_VERSION
        assert snapshot.runtime_platform == platform_identity
        assert snapshot.runtime_platform.digest == platform_identity.digest
        assert snapshot.runtime_platform.operating_system in {"linux", "windows"}
        assert snapshot.runtime_platform.architecture == "x86_64"
        assert snapshot.runtime_platform.binary_format in {"elf", "pe"}
        assert snapshot.runtime_platform.abi in {"manylinux_2_17_x86_64", "win_amd64"}
        assert snapshot.runtime_platform.python_implementation == "cpython"
        assert snapshot.runtime_platform.python_abi

        subsystems = {item.name: item for item in snapshot.subsystem_states}
        assert subsystems["runtime_platform"].state == "available"
        assert subsystems["runtime_platform"].identity_digest == platform_identity.digest

        native = native_decoder_resource_state()
        native_state = subsystems["native_decoder"]
        assert native_state.state == ("available" if native.available else "unavailable")
        assert native_state.identity_digest == (native.identity_digest if native.available else "")

        typescript = javascript_typescript_parser_resource_state()
        typescript_state = subsystems["typescript_parser_runtime"]
        assert typescript_state.state == ("available" if typescript.available else "unavailable")
        assert typescript_state.identity_digest == (
            typescript.resource_digest if typescript.available else ""
        )

        rebuilt = scan_session_snapshot_from_record(snapshot.to_record())
        assert rebuilt == snapshot
        assert validate_scan_session_runtime(snapshot) is snapshot
        publication = snapshot.publication_record()
        assert publication["runtime_platform"] == platform_identity.to_record()
        assert publication["runtime_platform_digest"] == platform_identity.digest
    finally:
        sqlite_lifecycle().close()
        if previous is None:
            os.environ.pop("UMIGE_BASE_DIR", None)
        else:
            os.environ["UMIGE_BASE_DIR"] = previous


def test_phase12_generation_changes_for_platform_or_packaged_parser_identity(tmp_path: Path) -> None:
    snapshot = _build(tmp_path)
    try:
        baseline = snapshot.generation_record()
        assert scan_session_generation_id(baseline) == snapshot.generation_id

        changed_platform = copy.deepcopy(baseline)
        changed_platform["runtime_platform"]["python_abi"] += "-changed"
        assert scan_session_generation_id(changed_platform) != snapshot.generation_id

        changed_dependency = copy.deepcopy(baseline)
        for item in changed_dependency["subsystem_states"]:
            if item["name"] == "typescript_parser_runtime" and item["state"] == "available":
                item["identity_digest"] = "f" * 64
                break
        else:
            raise AssertionError("typescript_parser_runtime_available_required_for_phase12_gate")
        assert scan_session_generation_id(changed_dependency) != snapshot.generation_id
    finally:
        sqlite_lifecycle().close()


def test_phase12_manifest_rejects_platform_drift_without_compatibility_path(tmp_path: Path) -> None:
    snapshot = _build(tmp_path)
    try:
        record = snapshot.to_record()
        record["runtime_platform"]["python_abi"] += "-changed"
        try:
            scan_session_snapshot_from_record(record)
        except ValueError as exc:
            assert str(exc) == "scan_session_generation_record_mismatch"
        else:
            raise AssertionError("platform drift must invalidate the current-schema session generation")
    finally:
        sqlite_lifecycle().close()


def test_phase12_worker_file_execution_uses_bootstrap_frozen_yara_selection() -> None:
    execution_source = inspect.getsource(inmemory_file_scan_steps.execute_inmemory_scan_context)
    bootstrap_source = inspect.getsource(inmemory_worker_bootstrap.configure_inmemory_worker_bootstrap)

    assert "context.compiled_rules" in execution_source
    assert "yara_rules_state" not in execution_source
    assert "selected_yara_snapshot" not in execution_source
    assert 'worker_config["compiled_rules"]' in bootstrap_source
    assert "initialized_yara = configure_worker_yara_runtime" in bootstrap_source
