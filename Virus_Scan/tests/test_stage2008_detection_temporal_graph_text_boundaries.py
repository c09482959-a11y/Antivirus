
"""Stage 2008 detection temporal graph no-hook text boundary regressions."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.detection.correlation.graph.temporal_graph import (
    _temporal_graph_confidence,
    _temporal_graph_text,
    _temporal_stage_hit_label,
)


class HostileTemporalValue:
    __slots__ = ("calls",)

    def __init__(self, calls: list[str]) -> None:
        object.__setattr__(self, "calls", calls)

    def __getattribute__(self, name: str):
        if name == "calls":
            return object.__getattribute__(self, name)
        object.__getattribute__(self, "calls").append("__getattribute__")
        raise AssertionError("caller-owned attribute hook executed")

    def __str__(self) -> str:
        self.calls.append("__str__")
        raise AssertionError("caller-owned str hook executed")

    def __repr__(self) -> str:
        self.calls.append("__repr__")
        raise AssertionError("caller-owned repr hook executed")

    def __bool__(self) -> bool:
        self.calls.append("__bool__")
        raise AssertionError("caller-owned bool hook executed")

    def __float__(self) -> float:
        self.calls.append("__float__")
        raise AssertionError("caller-owned float hook executed")

    def __round__(self, ndigits=None):
        self.calls.append("__round__")
        raise AssertionError("caller-owned round hook executed")



def test_temporal_graph_text_uses_default_text_without_caller_hooks_or_fallback_keyword():
    calls: list[str] = []
    text, reason = _temporal_graph_text(HostileTemporalValue(calls), default_text="unknown")

    assert text == "unknown"
    assert reason == "unsafe_temporal_graph_text_rejected"
    assert calls == []



def test_temporal_stage_hit_label_uses_owned_primitive_text():
    assert _temporal_stage_hit_label("network_download") == "stage:network_download"



def test_temporal_graph_confidence_rejects_hostile_numeric_hooks():
    calls: list[str] = []

    assert _temporal_graph_confidence(HostileTemporalValue(calls)) == 0.0
    assert calls == []



def test_detection_temporal_graph_repaired_source_snippets_absent():
    source = read_python_file(Path("Virus_Scan/detection/correlation/graph/temporal_graph.py"))
    forbidden = (
        "fallback: str = ''",
        "return str.__str__(fallback), reason",
        "stage, _stage_reason = _temporal_graph_text(dict.get(event_mapping, 'stage'), fallback='unknown')",
        "tag, _tag_reason = _temporal_graph_text(dict.get(event_mapping, 'tag'), fallback='')",
        "curr_stage, _curr_reason = _temporal_graph_text(curr_stage, fallback=normalize_stage(''))",
        "prev_stage, _prev_reason = _temporal_graph_text(prev_stage, fallback='unknown')",
        "hits.extend([f'stage:{h}' for h in _temporal_graph_text_sequence(stage_hits[:12], unsupported_reason='unsafe_stage_hit_rejected')])",
        "'confidence': round(safe_clamp(confidence), 6),",
        "path_text, _path_reason = _temporal_graph_text(path, fallback='<unknown>')",
    )
    for snippet in forbidden:
        assert snippet not in source

from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_registry import ATTACK_INTELLIGENCE_CLASSIFIERS


def test_attack_intelligence_probability_rejects_hostile_numeric_hooks():
    calls: list[str] = []

    assert ATTACK_INTELLIGENCE_CLASSIFIERS[0].calibrate(HostileTemporalValue(calls)) == 0.0
    assert calls == []


def test_attack_intelligence_repaired_source_snippets_absent():
    source = read_python_file(Path("Virus_Scan/detection/correlation/multi_signal/attack_intelligence.py"))
    forbidden = (
        'raise RuntimeError(f"unknown attack-intelligence classifier: {classifier_name}")',
        "'attack_score': safe_clamp(total / 60.0),",
    )
    for snippet in forbidden:
        assert snippet not in source

from Virus_Scan.detection.correlation.multi_signal.cluster_feature_tags import _cluster_decoded_behavior_tag
from Virus_Scan.detection.correlation.multi_signal.cluster_result import ClusterAssignment


def test_cluster_feature_behavior_tag_uses_owned_primitive_name():
    assert _cluster_decoded_behavior_tag("exec") == "cluster_decoded_behavior_exec"


def test_cluster_assignment_rejects_hostile_label_hooks():
    calls: list[str] = []

    assignment = ClusterAssignment(HostileTemporalValue(calls))  # type: ignore[arg-type]

    assert str.__str__(assignment) == "unclustered"
    assert calls == []


def test_cluster_repaired_source_snippets_absent():
    feature_source = read_python_file(Path("Virus_Scan/detection/correlation/multi_signal/cluster_feature_tags.py"))
    result_source = read_python_file(Path("Virus_Scan/detection/correlation/multi_signal/cluster_result.py"))

    assert 'features.append(f"cluster_decoded_behavior_{name}")' not in feature_source
    assert 'obj = str.__new__(cls, str(label or "unclustered"))' not in result_source

from Virus_Scan.detection.correlation.multi_signal.context_confidence import _graph_context_confidence


def test_graph_context_confidence_rejects_hostile_numeric_hooks():
    calls: list[str] = []

    assert _graph_context_confidence(HostileTemporalValue(calls)) == 0.0
    assert calls == []


def test_context_confidence_repaired_source_snippets_absent():
    source = read_python_file(Path("Virus_Scan/detection/correlation/multi_signal/context_confidence.py"))
    assert "confidence = safe_clamp(graph_score / 100.0 * cap)" not in source


def test_ordered_events_legacy_alias_exports_removed():
    source = read_python_file(Path("Virus_Scan/detection/correlation/temporal/ordered_events.py"))
    assert "_DEFAULT_TAG_ALIAS_REPORTING_MAP = _VOCAB_DEFAULT_TAG_ALIAS_REPORTING_MAP" not in source
    assert "_DEFAULT_CANONICAL_TAG_ALIASES = _VOCAB_DEFAULT_CANONICAL_TAG_ALIASES" not in source

from Virus_Scan.detection.correlation.temporal.timeline import (
    _timeline_probability,
    _timeline_transition_label,
    timeline_transitions,
)


def test_timeline_transition_labels_use_owned_primitive_text():
    events, transitions, behaviors, behavior_transitions = timeline_transitions(("network_download", "process_exec"))

    assert events == ["network_download", "process_exec"]
    assert transitions == ["network_download->process_exec"]
    assert all(type(item) is str for item in behavior_transitions)
    assert _timeline_transition_label("left", "right") == "left->right"


def test_timeline_probability_rejects_hostile_numeric_hooks():
    calls: list[str] = []

    assert _timeline_probability(HostileTemporalValue(calls)) == 0.0
    assert calls == []


def test_temporal_timeline_repaired_source_snippets_absent():
    source = read_python_file(Path("Virus_Scan/detection/correlation/temporal/timeline.py"))
    forbidden = (
        "transitions = [f'{events[i]}->{events[i + 1]}' for i in range(len(events) - 1)]",
        "behavior_transitions = [f'{behaviors[i]}->{behaviors[i + 1]}' for i in range(len(behaviors) - 1)]",
        "event_rare = sum((1.0 - safe_clamp(float(count) / denominator) for count in event_values)) / max(1, len(event_values))",
        "transition_rare = sum((1.0 - safe_clamp(float(count) / denominator) for count in transition_values)) / max(1, len(transition_values)) if transition_values else 0.0",
        "behavior_rare = sum((1.0 - safe_clamp(float(count) / denominator) for count in behavior_values)) / max(1, len(behavior_values))",
        "behavior_transition_rare = sum((1.0 - safe_clamp(float(count) / denominator) for count in behavior_transition_values)) / max(1, len(behavior_transition_values)) if behavior_transition_values else 0.0",
        "high_risk_boost = safe_clamp(never_seen_high_risk / max(1, len(events)))",
        "anomaly = safe_clamp(event_rare * 0.22 + transition_rare * 0.36 + behavior_rare * 0.12 + behavior_transition_rare * 0.2 + high_risk_boost * 0.1)",
        "return {'ready': True, 'anomaly': anomaly, 'event_rarity': safe_clamp(event_rare), 'transition_rarity': safe_clamp(transition_rare), 'behavior_rarity': safe_clamp(behavior_rare), 'behavior_transition_rarity': safe_clamp(behavior_transition_rare), 'never_seen_high_risk_events': never_seen_high_risk, 'sample_count': samples, 'events_seen': len(events), 'transitions_seen': len(transitions)}",
    )
    for snippet in forbidden:
        assert snippet not in source
