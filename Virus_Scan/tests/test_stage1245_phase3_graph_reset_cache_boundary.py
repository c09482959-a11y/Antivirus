from __future__ import annotations

from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence

from Virus_Scan.models.graph import get_graph_risk_enhanced, incremental_graph_update
from Virus_Scan.runtime.cache_state import runtime_cache_by_name
from Virus_Scan.runtime.graph_state import reset_graph_state


def test_stage1245_graph_reset_clears_graph_model_read_caches() -> None:
    reset_graph_state()
    node = "stage1245_graph_reset_cache.exe"
    incremental_graph_update(node, tag_evidence=normalize_tag_evidence(("process_exec", "network_download")))
    assert get_graph_risk_enhanced(node) >= 0.0

    cache = runtime_cache_by_name("GRAPH_RISK_CACHE")
    assert any(str(key).endswith(node) for key in cache)

    reset_graph_state()

    assert not runtime_cache_by_name("GRAPH_RISK_CACHE")
    assert not runtime_cache_by_name("GRAPH_PROPAGATION_CACHE")
    assert not runtime_cache_by_name("GRAPH_ATTENTION_CACHE")
