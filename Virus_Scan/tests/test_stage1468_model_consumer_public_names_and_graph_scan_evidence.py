from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.models.graph.scan import scan_cs


MODEL_CONSUMER_BOUNDARY_FILES = (
    Path("Virus_Scan/routing/graph_model_projection.py"),
    Path("Virus_Scan/routing/profile_model_projection.py"),
    Path("Virus_Scan/contracts/profile_context_identity.py"),
)


def _private_import_aliases(path: Path) -> set[tuple[str, str, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    aliases: set[tuple[str, str, str]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.asname and alias.asname.startswith("_") and alias.asname != "__all__":
                    aliases.add((node.module, alias.name, alias.asname))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname and alias.asname.startswith("_"):
                    aliases.add((alias.name, alias.name, alias.asname))
    return aliases


def test_stage1468_model_consumer_boundaries_do_not_private_alias_public_contracts() -> None:
    offenders = {
        str(path): sorted(_private_import_aliases(path))
        for path in MODEL_CONSUMER_BOUNDARY_FILES
        if _private_import_aliases(path)
    }

    assert offenders == {}


def test_stage1468_graph_scan_owner_emits_unavailable_evidence_instead_of_empty_clean_list(tmp_path: Path) -> None:
    missing = tmp_path / "missing.cs"

    assert scan_cs(missing) == ["graph_cs_scan_unavailable"]
