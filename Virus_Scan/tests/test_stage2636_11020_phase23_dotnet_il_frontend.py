"""Phase 23 bounded ECMA-335 .NET IL frontend regressions."""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path

import pytest

from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
from Virus_Scan.routing.extension_scan_router import scan_file_by_type
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.scanners.static_program_analysis import (
    DOTNET_IL_FRONTEND_DIGEST,
    DOTNET_IL_FRONTEND_SCHEMA_VERSION,
    DOTNET_IL_MAX_SOURCE_BYTES,
    DOTNET_IL_PARSER_SCHEMA_VERSION,
    DotNetILNotApplicable,
    DotNetILParseError,
    STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_EXTENSION,
    STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_SCANNER_ID,
    STATIC_PROGRAM_ANALYSIS_FRONTENDS,
    analyze_dotnet_il_snapshot,
    dotnet_il_analysis_dependency_digest,
    parse_dotnet_il,
)
from Virus_Scan.storage import scan_cache_repository, sqlite_lifecycle
from Virus_Scan.stress.static_semantic_binary_fixtures import (
    build_managed_dotnet_fixture,
    build_native_pe_control,
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


def _write_fixture(path: Path, *, documentation_only: bool = False) -> Path:
    path.write_bytes(build_managed_dotnet_fixture(documentation_only=documentation_only))
    return path


def _analysis(path: Path):
    return analyze_dotnet_il_snapshot(build_artifact_read_snapshot(path)).analysis


def _by_kind(analysis, kind: str):
    return tuple(item for item in analysis.operations if item.operation_kind == kind)


def test_phase23_dotnet_registry_has_one_frontend_owner() -> None:
    expected = (
        "javascript_typescript_static_analysis",
        "powershell_static_analysis",
        "batch_cmd_static_analysis",
        "shell_static_analysis",
        "dotnet_il_static_analysis",
        "native_elf_x86_64_static_analysis",
        "python_renpy_static_analysis",
    )
    assert tuple(item.scanner_id for item in STATIC_PROGRAM_ANALYSIS_FRONTENDS) == expected
    frontend = STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_SCANNER_ID["dotnet_il_static_analysis"]
    assert STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_EXTENSION[".dll"] is frontend
    assert STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_EXTENSION[".exe"] is frontend
    assert frontend.frontend_digest == DOTNET_IL_FRONTEND_DIGEST
    assert frontend.schema_version == DOTNET_IL_FRONTEND_SCHEMA_VERSION
    assert dotnet_il_analysis_dependency_digest() == DOTNET_IL_FRONTEND_DIGEST


def test_phase23_dotnet_parser_reads_real_metadata_il_and_dead_code() -> None:
    module = parse_dotnet_il(build_managed_dotnet_fixture())
    assert module.runtime_version == "v4.0.30319"
    assert module.entrypoint_token == 0x06000001
    assert tuple(method.name for method in module.methods) == ("Main", "Dead")
    assert module.methods[0].reachable_offsets == frozenset(
        instruction.offset for instruction in module.methods[0].instructions
    )
    assert module.methods[1].reachable_offsets == frozenset({0, 13})
    assert 7 not in module.methods[1].reachable_offsets
    references = module.reference_by_token()
    assert references[0x0A000001].full_name == "System.IO.File::ReadAllBytes"
    assert references[0x0A000002].full_name == "System.Net.Http.HttpClient::PostAsync"
    assert references[0x06000003].effective_name == "OpenProcess"
    assert references[0x06000003].pinvoke_module == "kernel32.dll"
    assert set(module.user_string_by_token().values()) == {
        "C:/Users/Test/Login Data",
        "https://example.invalid/upload",
        "calc.exe",
    }
    assert DOTNET_IL_PARSER_SCHEMA_VERSION == "dotnet_il_parser_v1"


def test_phase23_dotnet_parser_fails_closed_on_nonmanaged_and_hostile_bounds() -> None:
    with pytest.raises(DotNetILNotApplicable):
        parse_dotnet_il(build_native_pe_control())

    excessive_sections = bytearray(build_managed_dotnet_fixture())
    pe_offset = int.from_bytes(excessive_sections[0x3C:0x40], "little")
    excessive_sections[pe_offset + 6:pe_offset + 8] = (97).to_bytes(2, "little")
    with pytest.raises(DotNetILParseError, match="section_count"):
        parse_dotnet_il(bytes(excessive_sections))

    invalid_branch = bytearray(build_managed_dotnet_fixture())
    invalid_branch[0x662] = 0x7F
    with pytest.raises(DotNetILParseError, match="branch_target"):
        parse_dotnet_il(bytes(invalid_branch))


def test_phase23_dotnet_frontend_projects_exact_flow_reachability_and_pinvoke(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = _write_fixture(tmp_path / "fixture.exe")
        analysis = _analysis(target)
        assert analysis.parser_status == "complete"
        assert analysis.integrity_status == "verified"
        assert analysis.language == "dotnet_il"
        source = _by_kind(analysis, "file_read")[0]
        sink = _by_kind(analysis, "network_send")[0]
        reachable_launch, dead_launch = sorted(
            _by_kind(analysis, "process_launch"),
            key=lambda item: item.reachability_state == "unreachable",
        )
        process_open = _by_kind(analysis, "process_open")[0]
        assert source.reachability_state == "entrypoint_reachable"
        assert source.resolved_arguments["target"] == "C:/Users/Test/Login Data"
        assert source.flow_identity.startswith("flow_")
        assert sink.reachability_state == "entrypoint_reachable"
        assert sink.resolved_arguments["target"] == "https://example.invalid/upload"
        assert sink.flow_identity == source.flow_identity
        assert any(
            edge.edge_kind == "source_to_sink"
            and edge.flow_identity == source.flow_identity
            and edge.source_operation_id == source.operation_id
            and edge.target_operation_id == sink.operation_id
            for edge in analysis.flow_edges
        )
        assert reachable_launch.reachability_state == "entrypoint_reachable"
        assert dead_launch.reachability_state == "unreachable"
        assert process_open.platform == "windows"
        assert process_open.resolved_arguments["call"] == "OpenProcess"
        assert process_open.resolved_arguments["pinvoke_module"] == "kernel32.dll"
        assert process_open.resolved_arguments["target"] == "0"
        assert process_open.target_resource_identity.startswith("res_")
        assert analysis.entrypoint_function_ids == (source.enclosing_function_id,)


def test_phase23_dotnet_metadata_references_and_strings_alone_mint_no_operations(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = _write_fixture(tmp_path / "documentation.dll", documentation_only=True)
        analysis = _analysis(target)
        assert analysis.parser_status == "complete"
        assert analysis.operations == ()
        assert analysis.flow_edges == ()


def test_phase23_dotnet_cache_is_exact_and_failed_or_unavailable_rows_are_not_reused(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = _write_fixture(tmp_path / "fixture.dll")
        snapshot = build_artifact_read_snapshot(target)
        first = analyze_dotnet_il_snapshot(snapshot)
        second = analyze_dotnet_il_snapshot(snapshot)
        assert first.cache_source == "computed"
        assert second.cache_source == "sqlite_cache"
        assert second.analysis.semantic_digest == first.analysis.semantic_digest

        malformed = bytearray(build_managed_dotnet_fixture())
        malformed[0x300:0x304] = b"FAIL"
        malformed_path = tmp_path / "malformed.dll"
        malformed_path.write_bytes(malformed)
        malformed_snapshot = build_artifact_read_snapshot(malformed_path)
        malformed_first = analyze_dotnet_il_snapshot(malformed_snapshot)
        malformed_second = analyze_dotnet_il_snapshot(malformed_snapshot)
        assert malformed_first.analysis.parser_status == "failed"
        assert malformed_second.analysis.parser_status == "failed"
        assert malformed_first.cache_source == malformed_second.cache_source == "computed"

        native_path = tmp_path / "native.exe"
        native_path.write_bytes(build_native_pe_control())
        native_snapshot = build_artifact_read_snapshot(native_path)
        native_first = analyze_dotnet_il_snapshot(native_snapshot)
        native_second = analyze_dotnet_il_snapshot(native_snapshot)
        assert native_first.analysis.parser_status == "unavailable"
        assert native_first.analysis.unavailable_reason.startswith("managed_cli_not_applicable:")
        assert native_first.cache_source == native_second.cache_source == "computed"


def test_phase23_dotnet_source_limit_fails_closed_and_is_not_cached(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "oversized.dll"
        fixture = build_managed_dotnet_fixture()
        target.write_bytes(fixture + b"\x00" * (
            DOTNET_IL_MAX_SOURCE_BYTES + 1 - len(fixture)
        ))
        snapshot = build_artifact_read_snapshot(target)
        first = analyze_dotnet_il_snapshot(snapshot)
        second = analyze_dotnet_il_snapshot(snapshot)
        assert first.analysis.parser_status == "truncated"
        assert first.analysis.integrity_status == "partial"
        assert first.analysis.limitations == ("source_size_limit_exceeded",)
        assert first.cache_source == second.cache_source == "computed"


def test_phase23_dotnet_physical_records_have_zero_attack_or_probability_authority(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = _write_fixture(tmp_path / "authority.exe")
        analysis = _analysis(target)
        payload = json.dumps(analysis.to_record(), sort_keys=True).casefold()
        assert "technique_id" not in payload
        assert "p_mitre" not in payload
        assert "probability" not in payload
        assert "runtime_occurrence" not in payload
        assert "execution_observed" not in payload


def test_phase23_dotnet_router_uses_canonical_plan_and_preserves_binary_detection(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = _write_fixture(tmp_path / "route.exe")
        snapshot = build_artifact_read_snapshot(target)
        outcome = scan_file_by_type(target, scan_session_snapshot=scan_session_snapshot_fixture(), artifact_read_snapshot=snapshot)
        summary = outcome.identity["static_program_analysis"]
        decisions = {
            item["scanner_id"]: item
            for item in outcome.identity["scanner_execution_plan"]["decisions"]
        }
        assert summary["scanner_id"] == "dotnet_il_static_analysis"
        assert summary["language"] == "dotnet_il"
        assert summary["parser_status"] == "complete"
        assert decisions["dotnet_il_static_analysis"]["outcome_status"] == "complete_with_observation"
        assert decisions["javascript_typescript_static_analysis"]["outcome_status"] == "not_applicable"
        assert decisions["shell_static_analysis"]["outcome_status"] == "not_applicable"
        assert "pe_file" in outcome.tags
        assert "static_file_read_operation" in outcome.tags
        assert "static_network_send_operation" in outcome.tags
        assert "static_process_open_operation" in outcome.tags
        assert "static_open_process_operation" in outcome.tags
        records = tuple(
            record for record in outcome.tag_evidence.records
            if record.source_detector == "dotnet_il_static_analysis"
        )
        assert records
        assert all(record.modality == "static_control_flow" for record in records)
        assert all(record.process_identity == "" and record.host_identity == "" for record in records)


def test_phase23_dotnet_parser_and_frontend_are_deterministic(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = _write_fixture(tmp_path / "deterministic.exe")
        first_module = parse_dotnet_il(target.read_bytes())
        second_module = parse_dotnet_il(target.read_bytes())
        assert first_module == second_module
        first = _analysis(target)
        scan_cache_repository().clear()
        second = _analysis(target)
        assert first.semantic_digest == second.semantic_digest
        assert first.to_record() == second.to_record()
