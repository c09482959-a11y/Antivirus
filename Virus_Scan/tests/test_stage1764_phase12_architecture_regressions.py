from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import (
    module_level_mutable_assignment_findings,
    parse_python_file,
    read_python_file,
    virus_scan_python_files,
)


import ast
from collections.abc import Mapping
import json
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch

from Virus_Scan.contracts import no_hook_materialization as canonical_no_hook
from Virus_Scan.models.clustering import graph_context
from Virus_Scan.models.clustering.graph_context import ClusterGraphNodeRecord
from Virus_Scan.models.contracts import no_hook_materialization as model_no_hook
from Virus_Scan.models.profiles.common import profile_safe_text
from Virus_Scan.publication.json_finalization import model_evidence_boundary
from Virus_Scan.scheduler.evidence.final_json_exact_fields import (
    collect_exact_scheduler_evidence,
)


PRODUCTION_ROOT = Path("Virus_Scan")


class HostileMapping(Mapping):
    touched = 0

    def __getitem__(self, _key):  # pragma: no cover - execution is failure
        type(self).touched += 1
        raise AssertionError("hostile mapping lookup executed")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile mapping iteration executed")

    def __len__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile mapping length executed")


class HostileSequence:
    touched = 0

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile sequence iteration executed")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile sequence truthiness executed")


class HostileProfileText:
    touched = 0

    @property
    def text(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile profile text descriptor executed")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile profile string conversion executed")


class HostileMetadata:
    touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile metadata string conversion executed")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile metadata repr executed")


def _production_files() -> tuple[Path, ...]:
    return virus_scan_python_files()


def _production_source(path_text: str) -> str:
    return read_python_file(Path(path_text))


def _production_tree_for(path: Path) -> ast.AST:
    return parse_python_file(path)


def _function_source(path: str, name: str) -> str:
    source = read_python_file(Path(path))
    tree = parse_python_file(Path(path))
    node = next(
        item
        for item in ast.walk(tree)
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and item.name == name
    )
    return ast.get_source_segment(source, node) or ""


def _source_needs_unsafe_pattern_ast_scan(source: str) -> bool:
    """Return whether the architecture guard needs to parse this module.

    The full-suite blocker was not a production defect; it was this regression
    guard reparsing every production module and building parent maps even when
    the source contained none of the forbidden tokens.  This prefilter is a
    pure source-token gate: it can only skip files that cannot contain any of
    the exact forbidden constructs asserted below.
    """
    if "HYBRID_GRAPH" in source:
        return True
    if "except" in source:
        return True
    if "__import__" in source or "import_module" in source:
        return True
    for line in source.splitlines():
        stripped = line.lstrip(" \t")
        if stripped == line:
            continue
        if stripped.startswith("import ") or stripped.startswith("from "):
            return True
    return False


def _collect_unsafe_pattern_offenders(path: Path) -> tuple[tuple[str, int, str], ...]:
    source = _production_source(str(path))
    if not _source_needs_unsafe_pattern_ast_scan(source):
        return ()

    offenders: list[tuple[str, int, str]] = []
    if "HYBRID_GRAPH" in source:
        offenders.append((str(path), 1, "hybrid_graph_token"))

    def visit(node: ast.AST, inside_function: bool = False) -> None:
        next_inside_function = inside_function or isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        )
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                offenders.append((str(path), node.lineno, "bare_except"))
            elif isinstance(node.type, ast.Name) and node.type.id in {
                "Exception",
                "BaseException",
            }:
                offenders.append((str(path), node.lineno, "broad_exception"))
        elif next_inside_function and isinstance(node, (ast.Import, ast.ImportFrom)):
            offenders.append((str(path), node.lineno, "function_scope_import"))
        elif isinstance(node, ast.Call):
            callee = node.func
            name = (
                callee.id
                if isinstance(callee, ast.Name)
                else callee.attr
                if isinstance(callee, ast.Attribute)
                else ""
            )
            if name in {"__import__", "import_module"}:
                offenders.append((str(path), node.lineno, "dynamic_import"))
        for child in ast.iter_child_nodes(node):
            visit(child, next_inside_function)

    visit(_production_tree_for(path))
    return tuple(offenders)


def test_stage1764_architecture_forbids_hybrid_graph_and_unsafe_import_patterns() -> None:
    offenders = [
        offender
        for path in _production_files()
        for offender in _collect_unsafe_pattern_offenders(path)
    ]
    assert offenders == []


def test_stage1764_architecture_forbids_raw_module_policy_mutables() -> None:
    offenders = [
        offender
        for path in _production_files()
        for offender in module_level_mutable_assignment_findings(path)
    ]
    assert offenders == []


def test_stage1764_architecture_model_no_hook_is_one_canonical_implementation() -> None:
    source_path = Path("Virus_Scan/models/contracts/no_hook_materialization.py")
    source = read_python_file(source_path)
    tree = parse_python_file(source_path)
    definitions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]

    assert definitions == []
    assert all(
        getattr(model_no_hook, name) is getattr(canonical_no_hook, name)
        for name in canonical_no_hook.__all__
    )


def test_stage1764_architecture_repaired_producers_have_no_old_empty_routes() -> None:
    extension_source = _function_source(
        "Virus_Scan/detection/evidence/behavioral/semantics.py",
        "extension_tag_probability",
    )
    bucket_source = _function_source(
        "Virus_Scan/detection/scoring/behavior/bucket_validation.py",
        "behavior_bucket_validation",
    )
    scheduler_source = _function_source(
        "Virus_Scan/scheduler/evidence/final_json_exact_fields.py",
        "collect_exact_scheduler_evidence",
    )
    queue_source = _function_source(
        "Virus_Scan/scheduler/runtime/queue_json_publication.py",
        "queue_write_claim_meta",
    )
    explain_source = read_python_file(Path("Virus_Scan/detection/explainability/evidence_builder.py"))

    assert "return 0.0" not in extension_source
    assert "read_extension_baseline_snapshot" in extension_source
    assert "behavior_bucket_probability_record" in bucket_source
    assert "behavior_bucket_probability(" not in bucket_source
    assert "collect_scheduler_evidence(value)" in scheduler_source
    assert "queue_claim_meta_write_failed" in queue_source
    assert "model_graph_influence(node)" in explain_source
    assert "model_temporal_drift(node)" in explain_source


def test_stage1764_architecture_clustering_rejects_hostile_snapshot_mapping() -> None:
    HostileMapping.touched = 0
    with patch.object(
        graph_context,
        "graph_snapshot",
        return_value=HostileMapping(),
    ):
        record = graph_context.cluster_graph_node_snapshot("hostile-map")

    assert HostileMapping.touched == 0
    assert record.available is False
    assert record.corrupt is True
    assert record.unavailable_reason == "graph_snapshot_corrupt"


def test_stage1764_architecture_clustering_rejects_hostile_snapshot_sequence() -> None:
    HostileSequence.touched = 0
    hostile = HostileSequence()
    node_data = MappingProxyType({"risk": 1.0, "tags": hostile, "edges": ()})
    with (
        patch.object(
            graph_context,
            "graph_snapshot",
            return_value=MappingProxyType({"hostile-sequence": node_data}),
        ),
        patch.object(graph_context, "graph_has_node", return_value=True),
        patch.object(
            graph_context,
            "graph_node_snapshot",
            return_value=node_data,
        ),
    ):
        record = graph_context.cluster_graph_node_snapshot("hostile-sequence")

    assert HostileSequence.touched == 0
    assert record.available is False
    assert record.corrupt is True
    assert record.unavailable_reason == "cluster_graph_tags_unavailable"


def test_stage1764_architecture_scheduler_unsupported_source_is_explicit() -> None:
    HostileSequence.touched = 0

    records = collect_exact_scheduler_evidence(HostileSequence())

    assert HostileSequence.touched == 0
    assert records
    payload = records[0].as_dict()
    assert payload["error_category"] == "scheduler_evidence_source_rejected"
    assert payload["final_json_must_record"] is True


def test_stage1764_architecture_publication_failure_is_not_empty_list() -> None:
    def fail_projection(_record):
        raise ValueError("projection failed")

    with patch.object(
        model_evidence_boundary,
        "build_model_evidence_final_json_fields",
        side_effect=fail_projection,
    ):
        projected = model_evidence_boundary.safe_model_evidence_final_json_fields({})

    assert isinstance(projected, dict)
    assert projected
    assert projected["model_evidence"]["final_json_must_record"] is True
    assert projected["model_evidence"]["model_failures"]


def test_stage1764_architecture_profile_text_does_not_probe_descriptors() -> None:
    HostileProfileText.touched = 0

    value = profile_safe_text(
        HostileProfileText(),
        replacement="profile_unavailable",
    )

    assert value == "profile_unavailable"
    assert HostileProfileText.touched == 0


def test_stage1764_architecture_model_to_json_rejects_hostile_metadata() -> None:
    HostileMetadata.touched = 0
    record = ClusterGraphNodeRecord(
        node_key="hostile-metadata",
        available=True,
        present=True,
        empty=False,
        corrupt=False,
        unavailable_reason="",
        risk=0.0,
        tags=(),
        edges=(),
        metadata=MappingProxyType({"hostile": HostileMetadata()}),
    )

    materialized = record.to_json()

    json.dumps(materialized, sort_keys=True, allow_nan=False)
    assert HostileMetadata.touched == 0
    assert (
        materialized["metadata"]["hostile"]["unavailable_reason"]
        == "non_materializable_cluster_graph_value"
    )
