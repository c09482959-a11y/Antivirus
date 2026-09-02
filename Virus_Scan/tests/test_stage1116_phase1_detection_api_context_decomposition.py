import ast
from pathlib import Path

from Virus_Scan.detection.enrichment.full_analysis.api_context import build_detection_api_context
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.scoring.escalation.high_gate import apply_anchor_chain_high_gate
from Virus_Scan.detection.scoring.full_analysis.layered_score import compute_layered_detection
from Virus_Scan.tests.support.canonical_chain_fixtures import causal_tag_evidence


_API_CONTEXT_PATH = Path("Virus_Scan/detection/enrichment/full_analysis/api_context.py")


def _api_graph(path, strings_blob, tags, *, strings_already_enriched, precomputed_tags):
    return {"api_calls": ("CreateFileA", "ShellExecuteW"), "sequence": ("CreateFileA", "ShellExecuteW")}


def _family_heuristics(*, path, tags, strings_blob, api_calls):
    return {"score": 3.0, "hits": ("renpy_family",), "api_count": len(api_calls)}


def test_stage1116_detection_api_context_helpers_stay_bounded_after_decomposition():
    tree = ast.parse(_API_CONTEXT_PATH.read_text(encoding="utf-8"))
    oversized = {
        node.name: node.end_lineno - node.lineno + 1
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.end_lineno - node.lineno + 1 > 40
    }

    assert oversized == {}


def test_stage1116_detection_api_context_preserves_enriched_fact_outputs():
    facts = build_detection_api_context(
        path="game/script.rpy", tags=("renpy_script",),
        strings_blob="init python: ShellExecuteW CreateFileA", strings_already_enriched=False,
        api_graph_enricher=_api_graph, family_heuristics_builder=_family_heuristics,
    )

    assert facts.api_result["api_calls"] == ("CreateFileA", "ShellExecuteW")
    assert facts.heur["hits"] == ("renpy_family",)
    assert facts.chain_evidence is not None
    assert facts.failure_evidence == ()


def test_stage1116_detection_api_context_api_enrichment_failure_remains_evidenced():
    def failing_api_graph(path, strings_blob, tags, *, strings_already_enriched, precomputed_tags):
        raise RuntimeError("injected api enrichment failure")

    facts = build_detection_api_context(
        path="game/broken.rpy", tags=("renpy_script",),
        strings_blob="init python: pass", strings_already_enriched=False,
        api_graph_enricher=failing_api_graph, family_heuristics_builder=_family_heuristics,
    )

    records = tuple(facts.failure_evidence)
    assert facts.api_result["api_calls"] == ()
    assert any(record["stage_name"] == "api_graph_enrichment" for record in records)
    assert any(record["json_record_required"] is True for record in records)
    assert any(record["replay_record_required"] is True for record in records)

_LAYERED_SCORE_PATH = Path("Virus_Scan/detection/scoring/full_analysis/layered_score.py")


def test_stage1116_layered_score_helpers_stay_bounded_after_decomposition():
    tree = ast.parse(_LAYERED_SCORE_PATH.read_text(encoding="utf-8"))
    oversized = {
        node.name: node.end_lineno - node.lineno + 1
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.end_lineno - node.lineno + 1 > 40
    }

    assert oversized == {}


def test_stage1116_layered_score_uses_canonical_chain_bundle_for_final_floor():
    tag_evidence = causal_tag_evidence(
        ("encoded_payload", "network_download", "process_exec"),
        correlation_group="decoded_network_execution",
        source_detector="stage1116",
    )
    chain_evidence = evaluate_chain_evidence(tags=tag_evidence)
    result = compute_layered_detection(
        "payload.dat",
        tag_evidence,
        chain_evidence,
        curr_stage="detection",
    )
    score, metadata = apply_anchor_chain_high_gate(
        result["score"],
        chain_evidence,
        tags=tag_evidence,
        path="payload.dat",
    )

    assert score >= 92.0
    assert "anchor:decoded_network_execution" in metadata["explicit_behavior_anchors"]
    assert "canonical_chain_evidence" not in result
