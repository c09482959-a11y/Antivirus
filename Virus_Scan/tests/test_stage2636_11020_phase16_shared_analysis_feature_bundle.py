"""Phase 18: the canonical ModelContextSnapshot replaces the shared bundle path."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.contracts.model_context_snapshot import ModelContextSnapshot
from Virus_Scan.contracts.model_projection_identity import model_projection_identity
from Virus_Scan.detection.correlation.multi_signal.model_context import build_detection_model_context
from Virus_Scan.detection.enrichment.full_analysis.api_context import build_detection_api_context
from Virus_Scan.detection.models.enriched_stage_outputs import DetectionEvidenceFacts
from Virus_Scan.detection.profiles.contracts import DetectionProfileContext, DetectionProfileSnapshot
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture

ROOT = Path(__file__).resolve().parents[2]


def _function_call_count(relative_path: str, function_name: str, called_name: str) -> int:
    tree = ast.parse((ROOT / relative_path).read_text(encoding="utf-8"))
    function = next(
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function_name
    )
    return sum(
        1 for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and (
            isinstance(node.func, ast.Name) and node.func.id == called_name
            or isinstance(node.func, ast.Attribute) and node.func.attr == called_name
        )
    )


def _profile_context(*, engine_context, path, tags, strings_blob):
    snapshot = DetectionProfileSnapshot(
        name="renpy", aliases=("renpy",), tag_markers=("renpy_script",),
        file_extensions=(".rpy",), baseline_suppression_profile="renpy",
        selected_engine_context_key="renpy",
    )
    return DetectionProfileContext(
        active_profile="renpy", selected_profile=snapshot,
        engine_context=engine_context,
        engine_confidence={"active_profile": "renpy", "failure_evidence": ()},
        selection_reasons=("phase18_test_profile",),
    )


def _api_graph(path, strings_blob, tags, *, strings_already_enriched, precomputed_tags):
    return {"api_calls": ("CreateFileW",), "sequence": ("CreateFileW",)}


def _family_heuristics(*, path, tags, strings_blob, api_calls):
    return {"score": 0.0, "hits": (), "api_count": len(api_calls)}


def test_phase18_full_analysis_chain_evaluation_has_one_canonical_owner() -> None:
    assert _function_call_count(
        "Virus_Scan/detection/enrichment/full_analysis/api_context.py",
        "_build_chain_evidence", "evaluate_chain_evidence",
    ) == 1
    assert _function_call_count(
        "Virus_Scan/detection/correlation/multi_signal/model_context.py",
        "build_detection_model_context", "evaluate_chain_evidence",
    ) == 0
    assert _function_call_count(
        "Virus_Scan/detection/scoring/adaptive/log_odds_fusion.py",
        "calibrated_log_odds_score_100", "evaluate_chain_evidence",
    ) == 0


def test_phase18_api_context_stops_at_authoritative_evidence_boundary() -> None:
    facts = build_detection_api_context(
        path="game/script.rpy", tags=("renpy_script",),
        strings_blob="label start:\n    pass", strings_already_enriched=True,
        api_graph_enricher=_api_graph, family_heuristics_builder=_family_heuristics,
    )
    assert type(facts) is DetectionEvidenceFacts
    assert not hasattr(facts, "model_context")
    assert not hasattr(facts, "graph_features")
    assert not hasattr(facts, "engine_context")


def test_phase18_model_context_binds_evidence_and_projection_generation_directly() -> None:
    session = scan_session_snapshot_fixture()
    evidence = build_detection_api_context(
        path="game/script.rpy", tags=("renpy_script",),
        strings_blob="label start:\n    pass", strings_already_enriched=True,
        api_graph_enricher=_api_graph, family_heuristics_builder=_family_heuristics,
    )
    snapshot = build_detection_model_context(
        "game/script.rpy", tags=evidence.tag_evidence,
        chain_evidence=evidence.chain_evidence,
        projection_identity=model_projection_identity(session),
        source_artifact_evidence_digest="a" * 64,
        file_structure="game/script.rpy", strings_blob="label start:\n    pass",
        api_calls=evidence.api_result.get("api_calls", ()),
        ordered_events=evidence.ordered_events,
        behavior_timeline=evidence.behavior_timeline,
        prev_stage="strings", curr_stage="detection", update_cluster=False,
        profile_context_builder=_profile_context,
    )
    assert type(snapshot) is ModelContextSnapshot
    assert snapshot.source_artifact_evidence_digest == "a" * 64
    assert snapshot.projection_identity == model_projection_identity(session)
    assert snapshot.profile_context["active_profile"] == "renpy"
    assert snapshot.to_record()["evidence_authority"] == "context_only"
    assert "tag_evidence" not in snapshot.to_record()
    assert "chain_evidence" not in snapshot.to_record()


def test_phase18_model_context_digest_invalidates_on_projection_identity_change() -> None:
    first = scan_session_snapshot_fixture(generation_seed="d")
    second = scan_session_snapshot_fixture(generation_seed="e")
    evidence = build_detection_api_context(
        path="game/script.rpy", tags=("renpy_script",), strings_blob="",
        strings_already_enriched=True, api_graph_enricher=_api_graph,
        family_heuristics_builder=_family_heuristics,
    )
    def build(session):
        return build_detection_model_context(
            "game/script.rpy", tags=evidence.tag_evidence,
            chain_evidence=evidence.chain_evidence,
            projection_identity=model_projection_identity(session),
            source_artifact_evidence_digest="b" * 64,
            file_structure="game/script.rpy", strings_blob="",
            api_calls=evidence.api_result.get("api_calls", ()),
            ordered_events=evidence.ordered_events,
            behavior_timeline=evidence.behavior_timeline,
            prev_stage="strings", curr_stage="detection", update_cluster=False,
            profile_context_builder=_profile_context,
        )
    assert build(first).semantic_digest != build(second).semantic_digest


def test_phase18_shared_bundle_production_path_is_deleted() -> None:
    assert not (ROOT / "Virus_Scan/detection/models/shared_analysis_feature_bundle.py").exists()
    assert not (ROOT / "Virus_Scan/contracts/shared_analysis_features.py").exists()
    production = ROOT / "Virus_Scan"
    for path in production.rglob("*.py"):
        if "tests" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        assert "SharedAnalysisFeatureBundle" not in text, path
        assert "shared_feature_bundle" not in text, path
