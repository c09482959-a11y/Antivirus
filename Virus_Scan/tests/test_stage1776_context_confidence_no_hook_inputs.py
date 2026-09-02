
"""Stage 1776 context confidence no-hook input boundary regressions."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.detection.correlation.multi_signal.context_confidence import (
    format_oddity_zscore,
    graph_context_uncertainty,
)


class HostileContextValue:
    str_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("hostile __str__ must not execute")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("hostile __bool__ must not execute")

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("hostile __iter__ must not execute")

    def __float__(self):
        type(self).float_calls += 1
        raise RuntimeError("hostile __float__ must not execute")


def _reset() -> None:
    HostileContextValue.str_calls = 0
    HostileContextValue.bool_calls = 0
    HostileContextValue.iter_calls = 0
    HostileContextValue.float_calls = 0


def _assert_no_hooks() -> None:
    assert HostileContextValue.str_calls == 0
    assert HostileContextValue.bool_calls == 0
    assert HostileContextValue.iter_calls == 0
    assert HostileContextValue.float_calls == 0


def test_format_oddity_rejects_hostile_tags_without_truthiness_or_iteration() -> None:
    _reset()

    result = format_oddity_zscore(path="sample.bin", entropy=None, tags=HostileContextValue())

    _assert_no_hooks()
    assert result["degraded"] is True
    assert any(failure["stage_name"] == "format_oddity_tag_context" for failure in result["failure_evidence"])
    assert result["confidence_source"] == "no_oddity_signal"


def test_format_oddity_rejects_hostile_entropy_without_float_hook() -> None:
    _reset()

    result = format_oddity_zscore(path="sample.bin", entropy=HostileContextValue(), tags=("high_entropy_packed",))

    _assert_no_hooks()
    assert result["entropy"] is None
    assert result["degraded"] is True
    assert result["confidence_source"] == "tag_inferred_oddity"
    assert any(failure["stage_name"] == "format_oddity_entropy_context" for failure in result["failure_evidence"])


def test_graph_context_uncertainty_rejects_hostile_tags_and_score_without_hooks() -> None:
    _reset()

    result = graph_context_uncertainty(node="node.bin", tags=HostileContextValue(), graph_score=HostileContextValue())

    _assert_no_hooks()
    assert result["raw_graph_score"] == 0.0
    assert result["degraded"] is True
    failure_stages = {failure["stage_name"] for failure in result["failure_evidence"]}
    assert "graph_context_tag_context" in failure_stages
    assert "graph_context_score_context" in failure_stages


def test_context_confidence_preserves_valid_exact_inputs() -> None:
    oddity = format_oddity_zscore(path="payload.bin", entropy="8.2", tags=("high_entropy_packed",))
    graph = graph_context_uncertainty(node="node.bin", tags=("process_exec", "network_download"), graph_score="80.0")

    assert oddity["entropy"] == 8.2
    assert oddity["confidence"] > 0.0
    assert oddity["degraded"] is False
    assert graph["raw_graph_score"] == 80.0
    assert graph["confidence"] > 0.0
    assert graph["degraded"] is False


def test_stage1776_context_confidence_source_blocks_hookable_conversion_patterns() -> None:
    source = read_python_file(Path("Virus_Scan/detection/correlation/multi_signal/context_confidence.py"))
    forbidden = (
        "normalize_tags(tags or [])",
        "{str(t).lower() for t in normalized_tags}",
        "float(entropy)",
        "float(graph_score or 0.0)",
    )
    assert [snippet for snippet in forbidden if snippet in source] == []
