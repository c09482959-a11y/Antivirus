from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

import Virus_Scan.scanners.text as text
from Virus_Scan.scanners import (
    text_api_graph,
    text_api_mapping,
    text_api_policy,
    text_api_sequence,
    text_api_timeline,
    text_graph_enrichment,
)



def test_text_api_graph_is_bounded_public_surface_not_mixed_owner_implementation():
    source = read_python_file(Path("Virus_Scan/scanners/text_api_graph.py"))
    assert len(source.splitlines()) <= 80
    assert "def " not in source
    assert "from Virus_Scan.scanners.text_api_policy" in source
    assert "from Virus_Scan.scanners.text_graph_enrichment" in source


def test_text_imports_canonical_api_modules_directly_after_graph_split():
    source = read_python_file(Path("Virus_Scan/scanners/text.py"))
    assert "from Virus_Scan.scanners.text_api_graph" not in source
    assert "from Virus_Scan.scanners.text_api_sequence" in source
    assert "from Virus_Scan.scanners.text_graph_enrichment" in source
    assert text.extract_api_calls is text_api_sequence.extract_api_calls
    assert text.enrich_with_api_and_graph is text_graph_enrichment.enrich_with_api_and_graph


def test_text_api_modules_preserve_public_contract_identity_after_split():
    assert text_api_graph.build_api_regex is text_api_policy.build_api_regex
    assert text_api_graph.map_api_to_group is text_api_policy.map_api_to_group
    assert text_api_graph.extract_api_calls is text_api_sequence.extract_api_calls
    assert text_api_graph.infer_tags_from_api is text_api_mapping.infer_tags_from_api
    assert text_api_graph.build_behavior_timeline is text_api_timeline.build_behavior_timeline
    assert text_api_graph.enrich_with_api_and_graph is text_graph_enrichment.enrich_with_api_and_graph


def test_text_api_graph_split_preserves_sequence_tags_and_graph_enrichment():
    blob = "CreateProcessW WriteProcessMemory CreateRemoteThread"
    sequence = text_api_sequence.extract_api_sequence_from_blob(blob)
    tags = text_api_mapping.infer_tags_from_api(sequence, [])
    result = text_graph_enrichment.enrich_with_api_and_graph(text_graph_enrichment.TextGraphEnrichmentRequest(
        "node",
        strings_blob=blob,
        strings_already_enriched=True,
        precomputed_tags=[],
    ))

    assert sequence == ["CreateProcessW", "WriteProcessMemory", "CreateRemoteThread"]
    assert "process_exec" in tags
    assert "process_injection" in tags
    assert result["api_calls"] == ["CreateProcessW", "WriteProcessMemory", "CreateRemoteThread"]
    assert "process_injection" in result["api_tags"]
    assert result["ordered_events"]
