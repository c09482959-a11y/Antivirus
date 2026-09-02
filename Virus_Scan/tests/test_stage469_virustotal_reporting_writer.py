from __future__ import annotations

import ast
import inspect
from pathlib import Path

from Virus_Scan.tests.support.static_inventory import read_python_file
from Virus_Scan.virustotal import reporting


def test_virustotal_has_no_independent_json_writer_or_merge_owner() -> None:
    source = read_python_file(Path("Virus_Scan/virustotal/reporting.py"))
    tree = ast.parse(source)
    imported_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert "Virus_Scan.reporting.json_writer" not in imported_modules
    assert "write_reporting_json" not in source
    assert "_write_result" not in source
    assert "_merge_previous" not in source
    assert "atomic_json_save" not in source


def test_virustotal_public_api_has_no_output_or_preserve_compatibility_path() -> None:
    parameters = inspect.signature(reporting.run_virustotal_reporting).parameters
    assert tuple(parameters) == ("results", "runtime")
    assert "output_path" not in parameters
    assert "preserve_results" not in parameters


def test_report_set_is_the_only_virustotal_filesystem_publication_owner() -> None:
    source = read_python_file(Path("Virus_Scan/publication/report_set.py"))
    assert "render_virustotal_publication" in source
    assert '"virustotal_results.json"' in source
    assert '"virustotal_findings_summary.json"' in source
    assert '"virustotal_findings_summary.md"' in source
    assert '"virustotal_findings_summary.csv"' in source
