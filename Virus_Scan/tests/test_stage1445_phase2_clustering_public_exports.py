from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file, read_python_file


import ast
from pathlib import Path

import Virus_Scan.models.clustering.api as clustering_api


def test_stage1445_clustering_api_exports_are_explicit_not_globals_dynamic() -> None:
    source = read_python_file(Path("Virus_Scan/models/clustering/api.py"))
    assert "globals()" not in source
    assert "tuple(name for name in" not in source
    assert "assign_cluster" in clustering_api.__all__
    assert "build_feature_vector" in clustering_api.__all__


def test_stage1445_clustering_export_tuple_contains_literal_names_only() -> None:
    tree = parse_python_file(Path("Virus_Scan/models/clustering/api.py"))
    all_assignment = next(
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets)
    )
    assert isinstance(all_assignment.value, ast.Tuple)
    assert all(isinstance(item, ast.Constant) and isinstance(item.value, str) for item in all_assignment.value.elts)
