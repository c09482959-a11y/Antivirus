import math

from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.scoring.full_analysis.layered_score import compute_layered_detection
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.models.graph import get_graph_risk_enhanced
from Virus_Scan.runtime.graph_state import add_graph_edge_owned, prune_graph_owned
from Virus_Scan.scanners.text import infer_tags_from_api


def test_layered_detection_does_not_leak_scheduler_previous_stage_without_file_order():
    tag_evidence = normalize_tag_evidence(
        ("process_exec", "network_download"),
        source_detector="stage391",
        source_stage="replay_determinism",
    )
    chain_evidence = evaluate_chain_evidence(tags=tag_evidence)
    serial = compute_layered_detection(
        "sample.exe", tag_evidence, chain_evidence, prev_stage="image", curr_stage="binary"
    )
    process = compute_layered_detection(
        "sample.exe", tag_evidence, chain_evidence, prev_stage="unknown", curr_stage="binary"
    )

    assert serial["layers"]["stage"]["previous_stage"] == "unknown"
    assert process["layers"]["stage"]["previous_stage"] == "unknown"
    assert serial["layers"] == process["layers"]
    assert serial["score"] == process["score"]


def test_api_tag_inference_is_hash_seed_stable():
    calls = ["CreateProcess", "InternetOpenUrl", "ReadFile"]
    tags_a = infer_tags_from_api(calls, {"credential_access", "network_activity"})
    tags_b = infer_tags_from_api(calls, {"network_activity", "credential_access"})

    assert tags_a == tags_b
    assert tags_a == sorted(tags_a, key=tags_a.index)


def test_graph_risk_enhanced_is_snapshot_deterministic_not_wall_clock_decay():
    node = "stage391_graph_node"
    prune_graph_owned()
    add_graph_edge_owned(node, "dst:late", weight=2.0)
    add_graph_edge_owned(node, "dst:early", weight=1.0)

    first = get_graph_risk_enhanced(node)
    second = get_graph_risk_enhanced(node)

    assert math.isclose(first, second, rel_tol=0.0, abs_tol=0.0)
