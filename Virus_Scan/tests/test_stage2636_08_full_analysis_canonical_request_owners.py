"""Canonical request-owner architecture for full-analysis scoring/publication."""
from __future__ import annotations

import ast
from dataclasses import fields
from pathlib import Path

from Virus_Scan.detection.orchestration.full_analysis.pipeline import (
    FullAnalysisPipelineDependencies,
    default_full_analysis_pipeline_dependencies,
)
from Virus_Scan.detection.publication import full_analysis_effects
from Virus_Scan.detection.scoring.full_analysis import input_builder, score_explained
from Virus_Scan.detection.scoring.full_analysis.stage_outputs import (
    DetectionDecision,
    ScoreBreakdown,
)


def _source(relative: str) -> str:
    return Path(relative).read_text(encoding="utf-8")


def test_stage2636_08_only_canonical_request_owners_are_public() -> None:
    assert input_builder.__all__ == ("ScoreContextRequest", "build_score_context")
    assert score_explained.__all__ == ("ScoreExplainedRequest", "score_explained")
    assert full_analysis_effects.__all__ == (
        "GraphPublicationRequest",
        "LearningPublicationRequest",
        "ScoredDetectionPublicationRequest",
        "publish_scored_detection_state",
    )
    assert not hasattr(input_builder, "build_score_context_from_request")
    assert not hasattr(score_explained, "score_explained_pure")
    assert not hasattr(score_explained, "score_explained_from_request")
    assert not hasattr(full_analysis_effects, "publish_scored_detection_state_from_request")
    assert not hasattr(ScoreBreakdown, "from_values")
    assert not hasattr(DetectionDecision, "from_values")


def test_stage2636_08_pipeline_has_one_required_owner_per_role() -> None:
    names = tuple(field.name for field in fields(FullAnalysisPipelineDependencies))
    assert "build_score_context_from_request" not in names
    assert "publish_scored_detection_state_from_request" not in names
    assert names.count("build_score_context") == 1
    assert names.count("publish_scored_detection_state") == 1
    deps = default_full_analysis_pipeline_dependencies()
    assert deps.build_score_context is input_builder.build_score_context
    assert deps.publish_scored_detection_state is full_analysis_effects.publish_scored_detection_state


def test_stage2636_08_pipeline_execution_has_no_parallel_fallback_branch() -> None:
    path = "Virus_Scan/detection/orchestration/full_analysis/pipeline_execution.py"
    source = _source(path)
    tree = ast.parse(source)
    assert "build_score_context_from_request" not in source
    assert "publish_scored_detection_state_from_request" not in source
    assert "Compatibility adapter" not in source
    attribute_names = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    assert "build_score_context_from_request" not in attribute_names
    assert "publish_scored_detection_state_from_request" not in attribute_names


def test_stage2636_08_canonical_files_contain_no_compatibility_markers() -> None:
    paths = (
        "Virus_Scan/detection/scoring/full_analysis/input_builder.py",
        "Virus_Scan/detection/scoring/full_analysis/score_explained.py",
        "Virus_Scan/detection/publication/full_analysis_effects.py",
        "Virus_Scan/detection/orchestration/full_analysis/pipeline.py",
        "Virus_Scan/detection/orchestration/full_analysis/pipeline_execution.py",
        "Virus_Scan/detection/scoring/full_analysis/stage_outputs.py",
    )
    forbidden = (
        "compatibility adapter",
        "compatibility wrapper",
        "compatibility alias",
        "fallback owner",
    )
    for path in paths:
        source = _source(path).lower()
        assert [marker for marker in forbidden if marker in source] == []
