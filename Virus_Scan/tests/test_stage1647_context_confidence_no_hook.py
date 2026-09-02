
"""Stage 1647: context confidence scoring must not call hostile hooks."""

from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from collections.abc import Mapping
from pathlib import Path

from Virus_Scan.detection.scoring.weighting.context_confidence import (
    compute_context_confidence_amplifier,
)


class HostileText:
    touched = 0

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("do not stringify context metadata")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("do not repr context metadata")


class HostileNumeric:
    touched = 0

    def __float__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("do not float context score")

    def __int__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("do not int context score")


class HostileMapping(Mapping):
    touched = 0

    def __getitem__(self, key):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("do not index hostile mapping")

    def __iter__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("do not iterate hostile mapping")

    def __len__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("do not len hostile mapping")

    def get(self, key, default=None):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("do not call hostile mapping get")

    def keys(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("do not call hostile mapping keys")


def _context_kwargs() -> dict[str, object]:
    return {
        "node": "sample.exe",
        "tags": ("process_exec", "network_download"),
        "pre_context_score": 50.0,
    }


def test_stage1647_context_unavailable_reason_rejects_hostile_text_without_hooks() -> None:
    HostileText.touched = 0

    result = compute_context_confidence_amplifier(
        **_context_kwargs(),
        layers={"graph": {"score": 100.0, "graph_unavailable_reason": HostileText()}},
        adaptive_learning={},
    )

    assert HostileText.touched == 0
    assert result["graph_score"] == 0.0
    assert result["applied_bonus"] == 0.0
    assert result["context_unavailable_reasons"] == {
        "graph": "unsafe_context_reason_value_rejected",
    }


def test_stage1647_context_score_rejects_hostile_numeric_without_hooks() -> None:
    HostileNumeric.touched = 0

    result = compute_context_confidence_amplifier(
        **_context_kwargs(),
        layers={"graph": {"score": HostileNumeric()}},
        adaptive_learning={"markov": {"markov_anomaly": HostileNumeric()}},
    )

    assert HostileNumeric.touched == 0
    assert result["graph_score"] == 0.0
    assert result["markov_signal"] == 0.0
    assert result["context_unavailable_reasons"] == {
        "graph": "invalid_context_layer_score",
        "markov": "invalid_context_model_signal",
    }


def test_stage1647_context_mapping_boundary_rejects_hostile_mapping_without_hooks() -> None:
    HostileMapping.touched = 0

    result = compute_context_confidence_amplifier(
        **_context_kwargs(),
        layers=HostileMapping(),
        adaptive_learning=HostileMapping(),
    )

    assert HostileMapping.touched == 0
    assert result["graph_score"] == 0.0
    assert result["intel_score"] == 0.0
    assert result["markov_signal"] == 0.0
    assert result["applied_bonus"] == 0.0


def test_stage1647_context_degraded_metadata_rejects_hostile_text_without_hooks() -> None:
    HostileText.touched = 0

    result = compute_context_confidence_amplifier(
        **_context_kwargs(),
        layers={},
        adaptive_learning={"markov": {"markov_anomaly": 1.0, "degraded": HostileText()}},
    )

    assert HostileText.touched == 0
    assert result["markov_signal"] == 0.0
    assert result["applied_bonus"] == 0.0
    assert result["context_unavailable_reasons"] == {
        "markov": "degraded_context_model_signal",
    }


def test_stage1647_context_confidence_source_removes_hookable_score_snippets() -> None:
    source = read_python_file(Path("Virus_Scan/detection/scoring/weighting/context_confidence.py"))
    tree = ast.parse(source)
    forbidden = (
        "return safe_clamp(signal), None",
        "return safe_clamp(final_score, 0.0, 100.0)",
        "vector_bonus = VECTOR_CLUSTER_MAX_BONUS * safe_clamp(cluster_quality.get('cluster_quality', 0.0))",
        "graph_signal = safe_clamp(graph_score / 100.0)",
        "intel_signal = safe_clamp(intel_score / 100.0)",
        "corroboration = safe_clamp(graph_signal * 0.5 + intel_signal * 0.3 + markov_signal * 0.2)",
        "applied_bonus = safe_clamp(final_after_context - pre_context_score, 0.0, COMBINED_CONTEXT_MAX_BONUS)",
        "hits.append(f'context_vector_cluster:+{min(vector_bonus, VECTOR_CLUSTER_MAX_BONUS):.2f}')",
        "hits.append(f'context_model_corroboration:+{min(corroboration_bonus, CONTEXT_CORROBORATION_MAX_BONUS):.2f}')",
    )
    assert [snippet for snippet in forbidden if snippet in source] == []
    assert [node for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)] == []
