from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

import Virus_Scan.dotnet as dotnet
import Virus_Scan.engine_route as engine_route
import Virus_Scan.publication.json_writer as final_report
import Virus_Scan.reporting.json_writer as json_writer
import Virus_Scan.stego as stego


def test_stage468_required_static_entrypoints_import_cleanly() -> None:
    assert final_report is not None
    assert json_writer is not None
    assert engine_route is not None
    assert dotnet is not None
    assert stego is not None


def test_stage468_orchestration_owns_static_reporting_and_scanner_entrypoints() -> None:
    runtime_source = read_python_file(Path("Virus_Scan/runtime_main.py"))
    runtime_tree = ast.parse(runtime_source)
    runtime_imported = set()
    for node in runtime_tree.body:
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                runtime_imported.add(f"{module}.{alias.name}")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                runtime_imported.add(alias.name)

    assert "Virus_Scan.orchestration.bootstrap_initialization" in runtime_imported
    assert "Virus_Scan.orchestration.lifecycle.run_scan_lifecycle" in runtime_imported
    assert "Virus_Scan.publication.json_writer" not in runtime_imported
    assert "Virus_Scan.reporting.json_writer" not in runtime_imported

    bootstrap_source = read_python_file(Path("Virus_Scan/orchestration/bootstrap_initialization.py"))
    bootstrap_tree = ast.parse(bootstrap_source)
    bootstrap_imported = set()
    for node in bootstrap_tree.body:
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                bootstrap_imported.add(f"{module}.{alias.name}")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                bootstrap_imported.add(alias.name)
    assert "Virus_Scan.scanners.api.public_contracts" in bootstrap_imported

    lifecycle_source = read_python_file(Path("Virus_Scan/orchestration/lifecycle.py"))
    lifecycle_tree = ast.parse(lifecycle_source)
    lifecycle_imported = set()
    for node in lifecycle_tree.body:
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                lifecycle_imported.add(f"{module}.{alias.name}")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                lifecycle_imported.add(alias.name)
    assert "Virus_Scan.publication.api.finalize_scan_results" in lifecycle_imported
    assert "Virus_Scan.publication.api.recover_results_from_partial" in lifecycle_imported
    assert "Virus_Scan.publication.json_writer.finalize_scan_results" not in lifecycle_imported
    assert "Virus_Scan.virustotal.reporting" in lifecycle_imported


def test_stage468_obsolete_finalizer_module_removed() -> None:
    assert not Path("Virus_Scan/reporting/finalizer.py").exists()
    runtime_source = read_python_file(Path("Virus_Scan/runtime_main.py"))
    assert "reporting import finalizer" not in runtime_source
    assert "Virus_Scan.reporting.finalizer" not in runtime_source
