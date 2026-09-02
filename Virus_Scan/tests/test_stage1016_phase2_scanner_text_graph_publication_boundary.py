from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scanners import text_graph_enrichment


def test_stage1016_scanner_text_graph_enrichment_does_not_import_model_graph() -> None:
    source_path = Path("Virus_Scan/scanners/text_graph_enrichment.py")
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=source_path.as_posix())

    forbidden: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and str(node.module or "").startswith("Virus_Scan.models.graph"):
            forbidden.append((node.lineno, node.module or ""))
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("Virus_Scan.models.graph"):
                    forbidden.append((node.lineno, alias.name))

    assert forbidden == []


def test_stage1016_scanner_text_graph_returns_publication_edges_without_side_effect_owner() -> None:
    result = text_graph_enrichment.enrich_with_api_and_graph(text_graph_enrichment.TextGraphEnrichmentRequest(
        "node",
        strings_blob="CreateProcessW WriteProcessMemory CreateRemoteThread",
        strings_already_enriched=True,
        precomputed_tags=[],
    ))

    assert "process_injection" in result["api_tags"]
    assert result["graph_publication_edges"]
    assert all(len(edge) == 4 for edge in result["graph_publication_edges"])
    assert result["graph_features"]["edges"] >= 2
