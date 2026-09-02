from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.contracts.call_graph_projection import (
    api_call_graph_features,
    immutable_api_call_graph,
)
from Virus_Scan.detection.enrichment.full_analysis import api_graph_context as detection_api_graph
from Virus_Scan.models import graph as model_graph
from Virus_Scan.scanners import text_graph_enrichment as scanner_api_graph


def test_stage1179_call_graph_projection_contract_is_immutable_and_deterministic():
    graph = immutable_api_call_graph(["B", "A", "C", "A", "C"])
    assert isinstance(graph, MappingProxyType)
    assert dict(graph) == {"A": ("C",), "B": ("A",), "C": ("A",)}
    assert api_call_graph_features(graph) == {"nodes": 3, "edges": 3, "density": 3 / (3 + 1e-6)}


def test_stage1179_detection_and_scanner_use_contract_not_local_graph_helpers():
    assert not hasattr(detection_api_graph, "build_call_graph")
    assert not hasattr(detection_api_graph, "call_graph_features")
    assert not hasattr(scanner_api_graph, "build_call_graph")
    assert not hasattr(scanner_api_graph, "call_graph_features")

    detection_result = detection_api_graph.enrich_with_api_and_graph(
        "sample.py",
        strings_blob="WriteFile DeleteFile WriteFile",
        strings_already_enriched=True,
        precomputed_tags=[],
    )
    scanner_result = scanner_api_graph.enrich_with_api_and_graph(scanner_api_graph.TextGraphEnrichmentRequest(
        "sample.py",
        strings_blob="WriteFile DeleteFile WriteFile",
        strings_already_enriched=True,
        precomputed_tags=[],
    ))

    assert detection_result["call_graph"] == {"DeleteFile": ("WriteFile",), "WriteFile": ("DeleteFile",)}
    assert dict(scanner_result["call_graph"]) == detection_result["call_graph"]
    assert detection_result["graph_features"] == scanner_result["graph_features"]


def test_stage1179_model_graph_no_longer_owns_api_call_graph_projection():
    assert not hasattr(model_graph, "build_call_graph")
    assert not hasattr(model_graph, "call_graph_features")
