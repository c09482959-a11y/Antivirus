
"""Phase 10: binary resource metrics must not hide unavailable telemetry as zero."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.scanners.binary_resource_metrics import _umige_process_rss_mb


def test_invalid_process_rss_uses_unavailable_sentinel():
    assert _umige_process_rss_mb(pid="not-a-pid") == -1.0


def test_binary_resource_metrics_do_not_return_zero_on_exception_paths():
    source = read_python_file(Path("Virus_Scan/scanners/binary_resource_metrics.py"))
    tree = ast.parse(source)
    lines = source.splitlines()
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            block = "\n".join(lines[node.lineno - 1:getattr(node, "end_lineno", node.lineno)])
            assert "return 0.0" not in block
            assert "pass" not in block
