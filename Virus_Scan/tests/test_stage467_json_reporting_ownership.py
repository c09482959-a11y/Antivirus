from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file

import ast
import logging
from argparse import Namespace
from pathlib import Path

from Virus_Scan.orchestration.lifecycle import configure_parsed
from Virus_Scan.runtime.context import RuntimeContext


def _close_file_handlers() -> None:
    root = logging.getLogger()
    for handler in tuple(root.handlers):
        if type(handler) is logging.FileHandler:
            root.removeHandler(handler)
            handler.close()


def test_cli_service_derives_one_scan_log_generation_without_dynamic_attribute_mutation(tmp_path: Path) -> None:
    source = read_python_file(Path("Virus_Scan/orchestration/lifecycle.py"))
    tree = ast.parse(source)
    assert not any(isinstance(node, ast.Call) and getattr(node.func, "id", "") == "setattr" for node in ast.walk(tree))

    target = tmp_path / "target"
    target.mkdir()
    args = Namespace(
        dir=str(target),
        scan_log_root=str(tmp_path / "Scan Logs"),
        scheduler="serial",
        no_scanlog=True,
    )
    configured = configure_parsed(RuntimeContext(), args)
    generation = Path(configured.scan_log_staging_path)
    assert Path(configured.output) == generation / "scan_results.json"
    assert Path(configured.log) == generation / "scanlog"
    assert not hasattr(configured, "vt_output")
    assert configured.scan_log_output_plan.report_path("virustotal_results.json") == Path(configured.scan_log_run_path) / "virustotal_results.json"
    assert Path(configured.scan_log_root) == (tmp_path / "Scan Logs").resolve()
    _close_file_handlers()


def test_resource_paths_do_not_use_globals_namespace_inspection() -> None:
    source = read_python_file(Path("Virus_Scan/runtime/resource_paths.py"))
    tree = ast.parse(source)
    assert not any(isinstance(node, ast.Call) and getattr(node.func, "id", "") == "globals" for node in ast.walk(tree))
