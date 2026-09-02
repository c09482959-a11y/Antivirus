from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from Virus_Scan.reporting import json_writer as reporting_json_writer
from Virus_Scan.reporting.json_writer import write_reporting_json
from Virus_Scan.runtime import scan_dependencies as deps


def _fresh_dependency_registry() -> deps.ScanDependencyRegistry:
    return deps.ScanDependencyRegistry()


def test_stage961_runtime_scan_dependency_fallbacks_emit_deterministic_string_evidence() -> None:
    registry = _fresh_dependency_registry()
    text = "powershell -enc AAAA https://example.test/payload DownloadString"

    assert deps.scan_strings(text, registry=registry) == [
        "powershell_exec",
        "encoded_powershell",
        "url_present",
        "network_download",
        "download_observable",
        "encoded_script_execution",
    ]
    assert deps.raw_stage_scan_strings(text, registry=registry) == deps.scan_strings(text, registry=registry)

    events = list(deps.iter_ordered_string_events(text, registry=registry))
    assert [offset for offset, _event in events] == sorted(offset for offset, _event in events)
    assert [event["tag"] for _offset, event in events] == [
        "powershell_exec",
        "encoded_powershell",
        "url_present",
        "network_download",
    ]


def test_stage961_runtime_scan_dependency_unregistered_ports_fail_closed() -> None:
    registry = _fresh_dependency_registry()
    assert deps.detect_target_engine_context("missing-root", registry=registry) == {
        "unity": 0.0,
        "renpy": 0.0,
        "rpgm": 0.0,
        "unknown": 1.0,
    }
    assert deps.intrastage_enabled(registry=registry) is False
    assert deps.stage_parallel_workers(registry=registry) == 1

    with pytest.raises(RuntimeError, match="raw task queue provider is not registered"):
        deps.run_raw_task_queue("job", registry=registry)
    with pytest.raises(RuntimeError, match="intrastage string task provider is not registered"):
        deps.append_intrastage_string_tasks("job", registry=registry)
    assert not hasattr(deps, "call_yara_cache_provider")


def test_stage961_reporting_json_writer_uses_atomic_json_boundary_and_preserves_backups(tmp_path: Path) -> None:
    target = tmp_path / "final_report.json"

    first_payload = {"status": "degraded", "evidence": [{"kind": "scheduler_timeout"}]}
    second_payload = {"status": "complete", "evidence": [{"kind": "scanner_evidence"}]}

    write_reporting_json(str(target), first_payload, backups=1)
    write_reporting_json(str(target), second_payload, backups=1)

    assert json.loads(target.read_text(encoding="utf-8")) == second_payload
    assert json.loads((tmp_path / "final_report.json.bak1").read_text(encoding="utf-8")) == first_payload


def test_stage961_runtime_and_reporting_dependency_modules_keep_static_public_boundaries() -> None:
    modules = [
        Path("Virus_Scan/runtime/scan_dependencies.py"),
        Path("Virus_Scan/reporting/json_writer.py"),
    ]

    for module_path in modules:
        source = module_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        function_scope_imports = [
            node
            for function in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))
            for node in ast.walk(function)
            if isinstance(node, (ast.Import, ast.ImportFrom))
        ]
        dynamic_imports = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and (
                (isinstance(node.func, ast.Name) and node.func.id == "__import__")
                or (isinstance(node.func, ast.Attribute) and node.func.attr == "import_module")
            )
        ]
        sys_modules_writes = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Attribute)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "sys"
            and node.value.attr == "modules"
        ]

        assert function_scope_imports == []
        assert dynamic_imports == []
        assert sys_modules_writes == []

    assert "write_reporting_json" in reporting_json_writer.__all__
