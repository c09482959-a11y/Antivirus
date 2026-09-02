from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file, read_python_file


import ast
from pathlib import Path

import Virus_Scan.models.graph.common as graph_common


def test_stage1444_graph_common_public_exports_are_explicit_not_globals_dynamic() -> None:
    source = read_python_file(Path("Virus_Scan/models/graph/common.py"))
    assert "globals()" not in source
    assert "tuple(name for name in" not in source
    assert isinstance(graph_common.__all__, tuple)
    assert "graph_has_node" not in graph_common.__all__
    assert "runtime_model_mapping_snapshot" not in graph_common.__all__
    assert "canonical_behavior_flow" not in graph_common.__all__


def test_stage1444_graph_common_export_tuple_contains_literal_names_only() -> None:
    tree = parse_python_file(Path("Virus_Scan/models/graph/common.py"))
    assignments = [node for node in tree.body if isinstance(node, ast.Assign)]
    all_assignment = next(node for node in assignments if any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets))
    assert isinstance(all_assignment.value, ast.Tuple)
    assert all(isinstance(item, ast.Constant) and isinstance(item.value, str) for item in all_assignment.value.elts)
