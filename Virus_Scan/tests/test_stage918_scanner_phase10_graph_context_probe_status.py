
"""Stage 918 Phase 10: graph probe status must not use hidden boolean defaults."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.scanners.binary_graph_context import binary_node_edge_status


class BrokenEdgeAccessor:
    def edges(self):
        raise RuntimeError("malformed graph accessor")


def test_graph_probe_error_status_still_visible():
    assert binary_node_edge_status(BrokenEdgeAccessor()) == ("probe_error", False)


def test_graph_context_exception_block_has_no_boolean_default_assignment():
    source = read_python_file(Path("Virus_Scan/scanners/binary_graph_context.py"))
    tree = ast.parse(source)
    for handler in [node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)]:
        block = ast.get_source_segment(source, handler) or ""
        assert "= True" not in block
        assert "= False" not in block
