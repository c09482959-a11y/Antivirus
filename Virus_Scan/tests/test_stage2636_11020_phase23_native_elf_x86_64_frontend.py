"""Phase 23 strict packaged Capstone and ELF64/x86-64 frontend regressions."""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

import pytest

from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
from Virus_Scan.contracts.runtime_platform_identity import runtime_platform_identity
from Virus_Scan.routing.extension_outcome import route_identity_record
from Virus_Scan.routing.context_identity import attach_routing_evidence_to_record
from Virus_Scan.routing.static_analysis_summary import (
    STATIC_ANALYSIS_SUMMARY_SCHEMA_VERSION,
    static_analysis_summary_record,
)
from Virus_Scan.routing.extension_scan_router import scan_file_by_type
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.publication.json_writer import compact_result_record
from packaged_capstone_5_0_9.integrity import (
    PACKAGED_CAPSTONE_DEPENDENCY_IDENTITY,
    PACKAGED_CAPSTONE_MANIFEST_SCHEMA_VERSION,
    validate_packaged_capstone,
    validate_packaged_capstone_target,
)
from Virus_Scan.scanners.static_program_analysis.native_capstone_runtime import (
    native_decoder_resource_state,
    open_native_decoder,
)
from Virus_Scan.scanners.static_program_analysis.native_elf_x86_64_frontend import (
    NATIVE_ELF_X86_64_FRONTEND_DIGEST,
    NATIVE_ELF_X86_64_FRONTEND_SCHEMA_VERSION,
    analyze_native_elf_x86_64_snapshot,
    native_elf_x86_64_analysis_dependency_digest,
)
from Virus_Scan.storage import scan_cache_repository, sqlite_lifecycle
from Virus_Scan.stress.static_semantic_binary_fixtures import (
    build_control_flow_fixture,
    build_elf64_x86_64,
    build_mid_instruction_target_fixture,
)


@contextmanager
def _isolated_runtime(tmp_path: Path):
    previous = os.environ.get("UMIGE_BASE_DIR")
    sqlite_lifecycle().close()
    runtime_root = tmp_path / "runtime"
    os.environ["UMIGE_BASE_DIR"] = str(runtime_root)
    try:
        scan_cache_repository().configure(runtime_root / "profiles", enabled=True)
        yield runtime_root
    finally:
        scan_cache_repository().configure(runtime_root / "profiles", enabled=False)
        sqlite_lifecycle().close()
        if previous is None:
            os.environ.pop("UMIGE_BASE_DIR", None)
        else:
            os.environ["UMIGE_BASE_DIR"] = previous


def _root() -> Path:
    return Path(__file__).resolve().parents[2]


def _package_root() -> Path:
    return _root() / "packaged_capstone_5_0_9"


def _write_fixture(tmp_path: Path, name: str, raw: bytes) -> Path:
    target = tmp_path / name
    target.write_bytes(raw)
    return target


def _analysis(path: Path):
    return analyze_native_elf_x86_64_snapshot(build_artifact_read_snapshot(path)).analysis


def test_phase23_packaged_capstone_identity_and_loaded_paths_are_exact() -> None:
    identity = native_decoder_resource_state()
    runtime = open_native_decoder()
    manifest = json.loads((_package_root() / "dependency_manifest.json").read_text(encoding="utf-8"))

    assert identity.available
    assert identity.identity_digest == PACKAGED_CAPSTONE_DEPENDENCY_IDENTITY
    assert manifest["schema_version"] == PACKAGED_CAPSTONE_MANIFEST_SCHEMA_VERSION
    assert manifest["dependency_identity_sha256"] == PACKAGED_CAPSTONE_DEPENDENCY_IDENTITY
    assert identity.distribution_version == "5.0.9"
    assert identity.binding_version == "5.0.7"
    assert identity.native_core_version == (5, 0, 1280)
    assert identity.required_core_exports == (
        "cs_close",
        "cs_disasm",
        "cs_free",
        "cs_open",
        "cs_option",
        "cs_version",
    )
    platform_identity = runtime_platform_identity()
    selected_target = next(
        item for item in manifest["targets"]
        if item["target"]["operating_system"] == identity.target_operating_system
        and item["target"]["architecture"] == identity.target_architecture
    )
    assert identity.target_operating_system == platform_identity.operating_system
    assert identity.target_architecture == platform_identity.architecture
    assert identity.target_abi == platform_identity.abi
    assert selected_target["native_core"]["required_exports"] == list(
        identity.required_core_exports
    )
    assert identity.native_core_sha256 == selected_target["native_core"]["sha256"]
    assert Path(identity.binding_path) == (_package_root() / "capstone/__init__.py").resolve()
    assert Path(identity.native_core_path) == (
        _root() / selected_target["native_core"]["path"]
    ).resolve()
    assert Path(runtime.binding.__file__).resolve() == Path(identity.binding_path)
    assert Path(runtime.binding._cs._name).resolve() == Path(identity.native_core_path)
    assert native_elf_x86_64_analysis_dependency_digest() == NATIVE_ELF_X86_64_FRONTEND_DIGEST


def test_phase27_windows_packaged_capstone_identity_is_static_and_exact() -> None:
    identity = validate_packaged_capstone_target(
        _package_root(),
        operating_system="windows",
        architecture="x86_64",
    )
    manifest = json.loads(
        (_package_root() / "dependency_manifest.json").read_text(encoding="utf-8")
    )
    windows_target = next(
        item for item in manifest["targets"]
        if item["target"]["operating_system"] == "windows"
    )

    assert identity.available
    assert identity.identity_digest == PACKAGED_CAPSTONE_DEPENDENCY_IDENTITY
    assert identity.target_operating_system == "windows"
    assert identity.target_architecture == "x86_64"
    assert identity.target_abi == "win_amd64"
    assert identity.native_core_sha256 == (
        "76958e18380023a68fd1714fa2e01c594cc6db1955a07ad6937b66e66dc5d6c3"
    )
    assert Path(identity.native_core_path) == (
        _package_root() / "capstone/lib/capstone.dll"
    ).resolve()
    assert windows_target["native_core"]["binary_format"] == "pe"
    assert windows_target["native_core"]["binary_class"] == "PE32+"
    assert windows_target["native_core"]["machine"] == "IMAGE_FILE_MACHINE_AMD64"
    assert windows_target["provenance"]["wheel_sha256"] == (
        "732cedbbb56d42e723f14d7af6387f1454194a820b4b96b56d1e53f865ef85d0"
    )


def test_phase23_packaged_binding_contains_no_host_or_environment_lookup() -> None:
    source = (_package_root() / "capstone/__init__.py").read_text(encoding="utf-8")
    forbidden = (
        "LIBCAPSTONE_PATH",
        "ctypes.util",
        "find_library",
        "sysconfig",
        "resources.files",
        "_path_list",
        "/usr/lib64",
        "/usr/local/lib",
        "libcapstone.so.5",
    )
    for token in forbidden:
        assert token not in source
    assert source.count("ctypes.CDLL(") == 1
    assert "ctypes.CDLL(_lib_path, mode=mode)" in source
    assert "_packaged_identity = _require_packaged_capstone()" in source
    assert "_lib_path = _packaged_identity.native_core_path" in source


def test_phase23_missing_packaged_core_does_not_fall_back_to_host(
    tmp_path: Path,
) -> None:
    identity = validate_packaged_capstone(_package_root())
    selected_relative = Path(identity.native_core_path).relative_to(_package_root())
    alternate_host_core = tmp_path / "host_capstone/lib" / selected_relative.name
    alternate_host_core.parent.mkdir(parents=True)
    shutil.copy2(_package_root() / selected_relative, alternate_host_core)

    copied = tmp_path / "packaged_capstone_5_0_9"
    shutil.copytree(_package_root(), copied, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (copied / selected_relative).unlink()
    assert alternate_host_core.is_file()
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join((str(tmp_path), str(_root())))
    environment["LIBCAPSTONE_PATH"] = str(alternate_host_core.parent)
    result = subprocess.run(
        [sys.executable, "-c", "import packaged_capstone_5_0_9.capstone"],
        cwd=tmp_path,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode != 0
    assert "packaged Capstone core is unavailable" in result.stderr
    assert str(alternate_host_core) not in result.stdout
    assert str(alternate_host_core) not in result.stderr


def test_phase23_corrupt_or_wrong_architecture_core_fails_manifest_validation(
    tmp_path: Path,
) -> None:
    selected = validate_packaged_capstone(_package_root())
    selected_relative = Path(selected.native_core_path).relative_to(_package_root())
    copied = tmp_path / "packaged_capstone_5_0_9"
    shutil.copytree(_package_root(), copied, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    core = copied / selected_relative
    raw = bytearray(core.read_bytes())
    raw[-1] ^= 0x01
    core.write_bytes(bytes(raw))

    identity = validate_packaged_capstone(copied)

    assert not identity.available
    assert identity.reason == "capstone_core_sha256_mismatch"


def test_phase23_control_flow_preserves_instruction_and_region_provenance(
    tmp_path: Path,
) -> None:
    target = _write_fixture(tmp_path, "control.elf", build_control_flow_fixture())
    analysis = _analysis(target)

    assert analysis.parser_status == "partial"
    assert analysis.integrity_status == "partial"
    assert analysis.parser_schema_version == NATIVE_ELF_X86_64_FRONTEND_SCHEMA_VERSION
    assert analysis.parser_digest == NATIVE_ELF_X86_64_FRONTEND_DIGEST
    assert "indirect_call:0x40100c" in analysis.unresolved_constructs
    assert {item.operation_kind for item in analysis.operations} == {
        "native_branch",
        "native_call",
        "native_return",
        "native_syscall",
    }
    assert {item.edge_kind for item in analysis.flow_edges} == {
        "branch_conditional",
        "branch_unconditional",
        "call_direct",
        "call_indirect",
        "control_return",
        "fallthrough",
    }
    assert any(item.edge_kind == "call_indirect" and item.resolution_state == "unresolved" for item in analysis.flow_edges)
    for operation in analysis.operations:
        arguments = operation.resolved_arguments
        assert arguments["architecture"] == "x86_64"
        assert arguments["mode"] == "64"
        assert arguments["endianness"] == "little"
        assert arguments["syntax"] == "intel"
        assert arguments["decoder_dependency_identity"] == PACKAGED_CAPSTONE_DEPENDENCY_IDENTITY
        assert arguments["section_identity"] == "elf_section:1:.text"
        assert arguments["executable_region_identity"] == "elf_exec_region:0:1"
        assert 0x100 <= arguments["file_offset"] < 0x111
        assert 0x401000 <= arguments["virtual_address"] < 0x401011
        assert len(arguments["instruction_byte_sha256"]) == 64
        assert operation.control_flow_provenance == "static_control_flow"
        assert operation.platform == "linux"
    operation_ids = {item.operation_id for item in analysis.operations}
    for edge in analysis.flow_edges:
        assert edge.source_operation_id in operation_ids
        if edge.target_operation_id:
            assert edge.target_operation_id in operation_ids


def test_phase23_mid_instruction_target_is_not_fabricated(
    tmp_path: Path,
) -> None:
    target = _write_fixture(tmp_path, "middle.elf", build_mid_instruction_target_fixture())
    analysis = _analysis(target)

    assert analysis.parser_status == "partial"
    assert analysis.limitations == ("control_flow_target_inside_instruction",)
    assert analysis.unresolved_constructs == ("target:0x401001",)
    assert len(analysis.operations) == 1
    operation = analysis.operations[0]
    assert operation.operation_kind == "native_branch"
    assert operation.resolution_state == "unresolved"
    assert operation.limitations == ("control_flow_target_inside_instruction",)
    assert analysis.flow_edges == ()


@pytest.mark.parametrize(
    ("name", "mutator", "reason"),
    (
        ("truncated.elf", lambda raw: raw[:20], "elf_header_truncated"),
        ("big_endian.elf", lambda raw: raw[:5] + b"\x02" + raw[6:], "elf_endianness_unsupported"),
        (
            "wrong_machine.elf",
            lambda raw: raw[:18] + struct.pack("<H", 3) + raw[20:],
            "elf_architecture_unsupported",
        ),
    ),
)
def test_phase23_malformed_or_unsupported_elf_abstains_without_operations(
    tmp_path: Path,
    name: str,
    mutator,
    reason: str,
) -> None:
    raw = build_elf64_x86_64(b"\x0f\x05\xc3")
    target = _write_fixture(tmp_path, name, mutator(raw))
    analysis = _analysis(target)

    assert analysis.parser_status == "failed"
    assert analysis.integrity_status == "unavailable"
    assert analysis.operations == ()
    assert analysis.flow_edges == ()
    assert reason in analysis.unavailable_reason


def test_phase23_complete_native_analysis_is_cached_but_partial_is_not(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        complete_path = _write_fixture(tmp_path, "complete.elf", build_elf64_x86_64(b"\x0f\x05\xc3"))
        complete_snapshot = build_artifact_read_snapshot(complete_path)
        first = analyze_native_elf_x86_64_snapshot(complete_snapshot)
        second = analyze_native_elf_x86_64_snapshot(complete_snapshot)
        assert first.analysis.parser_status == "complete"
        assert first.analysis.integrity_status == "verified"
        assert first.cache_source == "computed"
        assert second.cache_source == "sqlite_cache"
        assert first.analysis.semantic_digest == second.analysis.semantic_digest

        partial_path = _write_fixture(tmp_path, "partial.elf", build_control_flow_fixture())
        partial_snapshot = build_artifact_read_snapshot(partial_path)
        partial_first = analyze_native_elf_x86_64_snapshot(partial_snapshot)
        partial_second = analyze_native_elf_x86_64_snapshot(partial_snapshot)
        assert partial_first.analysis.parser_status == "partial"
        assert partial_first.cache_source == "computed"
        assert partial_second.cache_source == "computed"
        assert scan_cache_repository().get_static_analysis(
            content_sha256=partial_snapshot.content_sha256,
            analysis_dependency_digest=native_elf_x86_64_analysis_dependency_digest(),
        ) is None


def test_phase23_router_uses_one_native_frontend_and_preserves_static_scope(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = _write_fixture(tmp_path, "route.bin", build_elf64_x86_64(b"\x0f\x05\xc3"))
        outcome = scan_file_by_type(
            str(target),
            scan_session_snapshot=scan_session_snapshot_fixture(),
            artifact_read_snapshot=build_artifact_read_snapshot(target),
        )
        identity = route_identity_record(outcome.identity)

        assert identity is not None
        summary = identity["static_program_analysis"]
        assert summary["scanner_id"] == "native_elf_x86_64_static_analysis"
        assert summary["language"] == "native_x86_64"
        assert summary["parser_status"] == "complete"
        assert summary["summary_schema_version"] == STATIC_ANALYSIS_SUMMARY_SCHEMA_VERSION
        assert summary["flow_edge_count"] >= 1
        published = attach_routing_evidence_to_record(
            {"tags": list(outcome.tags)},
            target,
            router_identity=outcome.identity,
        )
        assert published["static_program_analysis"] == static_analysis_summary_record(summary)
        compact = compact_result_record(published)
        assert compact["static_program_analysis"] == static_analysis_summary_record(summary)
        assert summary["semantic_digest"] == _analysis(target).semantic_digest
        decisions = {
            item["scanner_id"]: item
            for item in identity["scanner_execution_plan"]["decisions"]
        }
        assert decisions["native_elf_x86_64_static_analysis"]["outcome_status"] == "complete_with_observation"
        assert decisions["dotnet_il_static_analysis"]["outcome_status"] == "not_applicable"
        records = tuple(
            record for record in outcome.tag_evidence.records
            if record.source_detector == "native_elf_x86_64_static_analysis"
        )
        assert records
        assert all(record.modality == "static_control_flow" for record in records)
        assert "static_native_syscall_operation" in outcome.tags
        assert "static_native_return_operation" in outcome.tags


def test_phase23_native_records_are_deterministic_and_have_no_attack_authority(
    tmp_path: Path,
) -> None:
    target = _write_fixture(tmp_path, "deterministic.elf", build_control_flow_fixture())
    first = _analysis(target)
    second = _analysis(target)
    record = first.to_record()
    text = json.dumps(record, sort_keys=True).casefold()

    assert first.semantic_digest == second.semantic_digest
    assert first.to_record() == second.to_record()
    assert "attack_technique" not in text
    assert "p_mitre" not in text
    assert "runtime_occurrence" not in text
    assert "execution_observed" not in text
    assert "operational_success" not in text
