from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.contracts.graph_publication import api_graph_publication_edges


def _source_tree(relative: str) -> ast.Module:
    return ast.parse(Path(relative).read_text(encoding="utf-8"))


def _function_named(tree: ast.Module, name: str) -> ast.FunctionDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"function not found: {name}")


def test_stage2082_core_paths_runtime_attack_tag_sets_have_no_duplicate_string_literals() -> None:
    tree = _source_tree("Virus_Scan/core/paths.py")
    target_functions = {
        "enforce_runtime_library_post_derive_gate",
        "runtime_library_score_cap",
        "suppress_runtime_binary_capability_noise",
    }
    failures: list[str] = []
    for function_name in target_functions:
        function = _function_named(tree, function_name)
        for node in ast.walk(function):
            if not isinstance(node, ast.Set):
                continue
            values = [
                element.value
                for element in node.elts
                if isinstance(element, ast.Constant) and isinstance(element.value, str)
            ]
            duplicates = sorted({value for value in values if values.count(value) > 1})
            if duplicates:
                failures.append(f"{function_name}:{node.lineno}:{duplicates}")
    assert failures == []


def test_stage2082_graph_publication_any_mapping_boundary_is_no_hook_contract() -> None:
    class HostileMapping(dict):
        def items(self):  # pragma: no cover - must not be called by the no-hook contract
            raise AssertionError("mapping hook invoked")

    edges = api_graph_publication_edges(
        "node",
        ["CreateFileW"],
        ["filesystem"],
        HostileMapping({"source": ["target"]}),
    )

    assert ("node", "api:CreateFileW", "api", 1.0) in edges
    assert ("node", "api_tag:filesystem", "api_tag", 1.5) in edges
    assert (
        "api:graph_publication_mapping_unavailable",
        "api:graph_publication_iterable_unavailable",
        "api_sequence",
        1.25,
    ) in edges
