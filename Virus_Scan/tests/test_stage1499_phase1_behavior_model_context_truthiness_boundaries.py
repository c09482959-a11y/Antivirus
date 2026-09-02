from __future__ import annotations

from Virus_Scan.tests.support.model_context_fixtures import model_projection_identity_fixture

import ast
from pathlib import Path

from Virus_Scan.detection.correlation.behavioral.behavior_flow import (
    detection_behavior_event_name,
    detection_behavior_flow,
)
from Virus_Scan.detection.correlation.multi_signal.model_context import (
    build_detection_model_context,
    detection_behavior_flow_from_sources,
)
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.scoring.weighting.scoreable_tags import scoreable_tag_evidence
from Virus_Scan.detection.correlation.multi_signal.model_projections import (
    detection_markov_features,
    detection_temporal_history_timeline,
    detection_temporal_snapshot,
)


class HostileBoolText:
    def __init__(self, value: str) -> None:
        self.value = value
        self.bool_calls = 0

    def __str__(self) -> str:
        return self.value

    def __bool__(self) -> bool:  # pragma: no cover - test fails if invoked
        self.bool_calls += 1
        raise AssertionError("caller-owned text truthiness was probed")


class HostileBoolIterable:
    def __init__(self, values) -> None:
        self.values = tuple(values)
        self.bool_calls = 0
        self.iter_calls = 0

    def __iter__(self):
        self.iter_calls += 1
        raise AssertionError("caller-owned iterable iteration was probed")

    def __bool__(self) -> bool:  # pragma: no cover - test fails if invoked
        self.bool_calls += 1
        raise AssertionError("caller-owned iterable truthiness was probed")


class HostileBoolDict(dict):
    def __bool__(self) -> bool:  # pragma: no cover - test fails if invoked
        raise AssertionError("caller-owned mapping truthiness was probed")


def test_stage1499_detection_behavior_flow_rejects_hostile_mapping_and_iterable_without_hooks() -> None:
    event = HostileBoolDict({"tag": HostileBoolText("api_CreateProcess")})
    flow_input = HostileBoolIterable([event, event, {"tag": "tag_network_download"}])

    assert detection_behavior_event_name(event) == ""
    assert detection_behavior_flow(flow_input) == []
    assert flow_input.bool_calls == 0
    assert flow_input.iter_calls == 0
    assert event["tag"].bool_calls == 0


def test_stage1499_detection_behavior_flow_preserves_exact_events() -> None:
    event = {"tag": "api_CreateProcess"}
    flow_input = (event, event, {"tag": "tag_network_download"})

    assert detection_behavior_event_name(event) == "createprocess"
    assert detection_behavior_flow(flow_input) == ["createprocess", "network_download"]


def test_stage1499_detection_behavior_flow_from_sources_rejects_hostile_source_without_hooks() -> None:
    behavior_flow = HostileBoolIterable([
        {"tag": HostileBoolText("api_OpenURL")},
        {"tag": "tag_network_download"},
    ])

    assert detection_behavior_flow_from_sources(behavior_flow=behavior_flow) == []
    assert behavior_flow.bool_calls == 0
    assert behavior_flow.iter_calls == 0


def test_stage1499_detection_behavior_flow_from_sources_preserves_exact_source() -> None:
    behavior_flow = (
        {"tag": "api_OpenURL"},
        {"tag": "tag_network_download"},
    )

    assert detection_behavior_flow_from_sources(behavior_flow=behavior_flow) == ["openurl", "network_download"]


def test_stage1499_model_context_build_rejects_hostile_optional_sequences_without_hooks() -> None:
    tags = HostileBoolIterable([HostileBoolText("tag_network_download")])
    ordered_events = HostileBoolIterable([{"tag": "api_CreateProcess"}, {"tag": "tag_network_download"}])
    api_calls = HostileBoolIterable([HostileBoolText("CreateProcessW")])

    tag_evidence = scoreable_tag_evidence(tags, allowed_evidence_kinds=frozenset({"observed", "normalized", "derived", "composite"}))
    ctx = build_detection_model_context(
        "sample.exe",
        tags=tag_evidence,
        chain_evidence=evaluate_chain_evidence(tags=tag_evidence),
        projection_identity=model_projection_identity_fixture(),
        source_artifact_evidence_digest="a" * 64,
        api_calls=api_calls,
        ordered_events=ordered_events,
        behavior_timeline=None,
        update_cluster=False,
        graph_features_builder=lambda node: {"risk": 0.0, "base_risk": 0.0, "anomaly": 0.0},
        temporal_snapshot_builder=lambda node, ordered_events=None, behavior_timeline=None: {"belief": 0.0, "flow": []},
        markov_features_builder=lambda prev, flow, curr: {"ready": bool(flow), "flow": list(flow)},
    )

    assert ctx.behavior_flow == ()
    assert tags.bool_calls == 0
    assert tags.iter_calls == 0
    assert ordered_events.bool_calls == 0
    assert ordered_events.iter_calls == 0
    assert api_calls.bool_calls == 0
    assert api_calls.iter_calls == 0


def test_stage1499_model_context_build_preserves_exact_optional_sequences() -> None:
    tag_evidence = scoreable_tag_evidence(("tag_network_download",), allowed_evidence_kinds=frozenset({"observed", "normalized", "derived", "composite"}))
    ctx = build_detection_model_context(
        "sample.exe",
        tags=tag_evidence,
        chain_evidence=evaluate_chain_evidence(tags=tag_evidence),
        projection_identity=model_projection_identity_fixture(),
        source_artifact_evidence_digest="a" * 64,
        api_calls=("CreateProcessW",),
        ordered_events=({"tag": "api_CreateProcess"}, {"tag": "tag_network_download"}),
        behavior_timeline=None,
        update_cluster=False,
        graph_features_builder=lambda node: {"risk": 0.0, "base_risk": 0.0, "anomaly": 0.0},
        temporal_snapshot_builder=lambda node, ordered_events=None, behavior_timeline=None: {"belief": 0.0, "flow": []},
        markov_features_builder=lambda prev, flow, curr: {"ready": bool(flow), "flow": list(flow)},
    )

    assert ctx.behavior_flow == ("createprocess", "network_download")


def test_stage1499_model_projections_reject_unknown_ordered_sequences_without_hooks() -> None:
    ordered_events = HostileBoolIterable([
        HostileBoolDict({"tag": HostileBoolText("tag_process_spawn"), "stage": HostileBoolText("scan"), "time": 0}),
        HostileBoolDict({"tag": "tag_network_download", "stage": "score", "time": 1}),
    ])

    temporal = detection_temporal_snapshot("sample.exe", ordered_events=ordered_events)
    timeline = detection_temporal_history_timeline("sample.exe", ordered_events=ordered_events)
    markov = detection_markov_features("scan", ordered_events, "score")

    assert temporal["ready"] is False
    assert temporal["reason"] == "insufficient_current_ordered_events"
    assert timeline == []
    assert markov["flow"] == []
    assert ordered_events.bool_calls == 0
    assert ordered_events.iter_calls == 0


def test_stage1499_model_projections_preserve_exact_ordered_sequences() -> None:
    ordered_events = (
        {"tag": "tag_process_spawn", "stage": "scan", "time": 0},
        {"tag": "tag_network_download", "stage": "score", "time": 1},
    )

    temporal = detection_temporal_snapshot("sample.exe", ordered_events=ordered_events)
    timeline = detection_temporal_history_timeline("sample.exe", ordered_events=ordered_events)
    markov = detection_markov_features("scan", ordered_events, "score")

    assert temporal["ready"] is True
    assert timeline[0]["stage"] == "scan"
    assert markov["flow"] == ["process_spawn", "network_download"]


def test_stage1499_behavior_context_sources_no_longer_use_truthiness_fallback_forms() -> None:
    checked = {
        Path("Virus_Scan/detection/correlation/behavioral/behavior_flow.py"),
        Path("Virus_Scan/detection/correlation/multi_signal/model_context.py"),
        Path("Virus_Scan/detection/correlation/multi_signal/model_projections.py"),
    }
    forbidden_snippets = (
        "events_or_tags or []",
        "behavior_flow or ()",
        "ordered_events or behavior_timeline",
        "value or {})",
        "tags or [])",
    )
    for path in checked:
        source = path.read_text(encoding="utf-8")
        for snippet in forbidden_snippets:
            assert snippet not in source
        ast.parse(source, filename=str(path))
