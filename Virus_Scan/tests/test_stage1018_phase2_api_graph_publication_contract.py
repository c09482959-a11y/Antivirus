from __future__ import annotations

from Virus_Scan.contracts.graph_publication import api_graph_publication_edges
from Virus_Scan.detection.enrichment.full_analysis import api_graph_context as detection_api_graph
from Virus_Scan.scanners import text_graph_enrichment as scanner_api_graph


def test_api_graph_publication_edges_are_shared_contract_not_cross_layer_duplicate():
    edges = api_graph_publication_edges(
        "sample.py",
        ["os.system"],
        ["process_exec"],
        {"os.system": ("subprocess.Popen",)},
    )
    assert edges == (
        ("sample.py", "api:os.system", "api", 1.0),
        ("sample.py", "api_tag:process_exec", "api_tag", 1.5),
        ("api:os.system", "api:subprocess.Popen", "api_sequence", 1.25),
    )
    assert scanner_api_graph.api_graph_publication_edges is api_graph_publication_edges
    assert detection_api_graph.api_graph_publication_edges is api_graph_publication_edges
