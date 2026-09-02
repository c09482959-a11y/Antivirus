from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.routing.graph_model_projection import route_cs_graph_tags

ROUTING_MODULES = (
    Path("Virus_Scan/routing/extension_scan_router.py"),
    Path("Virus_Scan/routing/extensions.py"),
)
PROJECTION_MODULE = Path("Virus_Scan/routing/graph_model_projection.py")


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    return imported


def test_stage1218_extension_routing_does_not_import_graph_model_directly() -> None:
    for path in ROUTING_MODULES:
        imported = _imported_modules(path)
        assert "Virus_Scan.models.graph" not in imported, (path, imported)
        assert all(not module.startswith("Virus_Scan.models.graph.") for module in imported), (path, imported)


def test_stage1218_extension_router_uses_routing_graph_projection_boundary() -> None:
    source = read_python_file(Path("Virus_Scan/routing/extension_scan_router.py"))
    assert "Virus_Scan.routing.graph_model_projection" in source
    assert "route_archive_members_to_graph(path)" in source
    assert "route_cs_graph_tags(path)" in source
    assert "link_archive_members_to_graph(path)" not in source
    assert "scan_cs(path)" not in source


def test_stage1218_projection_uses_public_graph_model_contract() -> None:
    imported = _imported_modules(PROJECTION_MODULE)
    assert "Virus_Scan.models.graph" not in imported
    assert "Virus_Scan.models.api.graph_contracts" in imported
    for path in ROUTING_MODULES:
        assert "Virus_Scan.models.graph" not in _imported_modules(path)


def test_stage1218_projection_preserves_graph_owned_cs_tags(tmp_path: Path) -> None:
    sample = tmp_path / "sample.cs"
    sample.write_text(
        "using System; class A { void B() { eval(\"x\"); Convert.FromBase64String(\"QQ==\"); } }",
        encoding="utf-8",
    )
    tags = set(route_cs_graph_tags(sample))
    assert "dynamic_code" in tags
    assert "base64" in tags
