from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
import inspect
from pathlib import Path

import Virus_Scan.models.api as model_api
from Virus_Scan.models import graph
from Virus_Scan.models.api import graph_contracts
from Virus_Scan.routing import graph_model_projection


def _imports_for(path: str) -> set[str]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
    return imports


def test_routing_graph_projection_uses_public_graph_contract() -> None:
    imports = _imports_for("Virus_Scan/routing/graph_model_projection.py")

    assert "Virus_Scan.models.graph" not in imports
    assert "Virus_Scan.models.api.graph_contracts" in imports
    source = read_python_file(Path("Virus_Scan/routing/graph_model_projection.py"))
    assert " as _graph_" not in source
    assert graph_model_projection.route_cs_graph_tags is not graph_contracts.scan_cs


def test_model_graph_public_contract_preserves_canonical_owner() -> None:
    assert "graph_contracts" in model_api.__all__
    assert graph_contracts.owner_scan_cs is graph.scan_cs
    assert graph_contracts.owner_link_archive_members_to_graph is graph.link_archive_members_to_graph
    assert inspect.getmodule(graph_contracts.owner_scan_cs).__name__ == "Virus_Scan.models.graph.scan"
    assert graph.scan_cs is graph_contracts.owner_scan_cs


def test_graph_public_contract_preserves_cs_tag_behavior(tmp_path: Path) -> None:
    sample = tmp_path / "sample.cs"
    sample.write_text(
        "using System; class A { void B() { eval(\"x\"); Convert.FromBase64String(\"QQ==\"); } }",
        encoding="utf-8",
    )

    tags = set(graph_contracts.scan_cs(sample))

    assert "dynamic_code" in tags
    assert "base64" in tags
