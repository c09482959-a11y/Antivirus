from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scanners.archives.publication_requests import (
    append_archive_graph_publication_request_tags,
    archive_graph_publication_edges,
)


def _imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
        elif isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
    return names


def test_archive_scanners_do_not_import_graph_mutation_owners():
    root = Path(__file__).resolve().parents[1]
    checked = [
        root / "scanners" / "archives" / "zip_scanner.py",
        root / "scanners" / "archives" / "tar_scanner.py",
    ]
    forbidden = {
        "Virus_Scan.models.graph",
        "Virus_Scan.runtime.graph_state",
    }
    for path in checked:
        imported = set(_imports(path))
        assert imported.isdisjoint(forbidden), (path, imported & forbidden)


def test_archive_graph_publication_requests_are_immutable_tagged_evidence():
    edges = archive_graph_publication_edges(
        edge_requests=(("parent.zip", "archive_member:parent.zip:payload.py", "archive_member", 1.0),)
    )
    assert edges == (("parent.zip", "archive_member:parent.zip:payload.py", "archive_member", 1.0),)

    tags: list[str] = []
    returned = append_archive_graph_publication_request_tags(
        tags,
        parent_path="parent.zip",
        member_name="payload.py",
        extracted_path="/tmp/payload.py",
        member_tags=("process_exec",),
        edge_requests=edges,
    )

    assert returned == edges
    assert "archive_graph_publication_requested" in tags
    assert "archive_graph_publication_edge_count:1" in tags
    assert "archive_graph_publication_member" in tags
    assert "archive_graph_publication_member_tags" in tags
    assert "archive_final_json_must_record" in tags
