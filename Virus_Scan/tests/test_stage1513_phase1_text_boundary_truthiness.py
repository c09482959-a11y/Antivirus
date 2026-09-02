"""Stage 1513 Phase 1 clustering/detection text-boundary truthiness regressions."""
from __future__ import annotations
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.detection.models.failure_state import DetectionRecoverableFailureRequest

from unittest.mock import patch
from Virus_Scan.models.clustering.common import dominant_engine_context, safe_cluster_text
from Virus_Scan.models.clustering import state as cluster_state_reader
from Virus_Scan.detection.correlation.multi_signal import model_projections
from Virus_Scan.detection.models.failure_state import DetectionFailureState
from Virus_Scan.detection.profiles.renpy import updater_text


class HostileText(str):
    def __new__(cls, value: str):
        obj = str.__new__(cls, value)
        obj.bool_calls = 0
        return obj

    def __str__(self):
        return self

    def strip(self, *args, **kwargs):
        return self

    def lower(self):
        return self

    def __bool__(self):  # pragma: no cover - failure proves boundary regression
        self.bool_calls += 1
        raise AssertionError("caller-owned text truthiness was probed")


def test_stage1513_clustering_common_text_helpers_detach_hostile_str_subclasses():
    text = HostileText("unity")
    fallback = HostileText("fallback")

    assert safe_cluster_text(text, default_text=fallback) == "unity"
    assert dominant_engine_context({text: 2.0}, default=fallback) == "unity"
    assert text.bool_calls == 0
    assert fallback.bool_calls == 0


def test_stage1513_cluster_graph_node_key_does_not_truth_test_runtime_key():
    key = HostileText("node:key")
    fallback = HostileText("fallback-node")
    with patch.object(cluster_state_reader, "graph_vector_node_key", lambda _node: key):
        assert cluster_state_reader.cluster_graph_node_key(fallback) == "node:key"

    assert key.bool_calls == 0
    assert fallback.bool_calls == 0


def test_stage1513_detection_model_projection_text_helpers_detach_hostile_text():
    tag = HostileText("network_download")
    stage = HostileText("runtime")

    timeline = model_projections.detection_temporal_history_timeline(
        "sample.bin",
        ordered_events=({"tag": tag, "stage": stage, "time": 1.0},),
    )
    cluster = model_projections.detection_cluster_projection(
        "sample.exe",
        tags=physical_tag_evidence(("network_download",)),
        engine_context={HostileText("unity"): 1.0},
    )

    assert timeline == [{"time": 1.0, "stage": "runtime", "tags": ["network_download"]}]
    assert cluster == "unity_exe_mixed_detection_projection"
    assert tag.bool_calls == 0
    assert stage.bool_calls == 0


def test_stage1513_detection_failure_state_does_not_truth_test_text_fields():
    stage = HostileText("stage-x")
    source = HostileText("model")
    context = HostileText("context-x")

    failure = DetectionFailureState.from_recoverable_request(DetectionRecoverableFailureRequest(
        stage_name=stage,
        error="boom",
        error_source=source,
        affected_context=context,
    ))

    assert failure.stage_name == "stage-x"
    assert failure.error_source == "model"
    assert failure.affected_context == "context-x"
    assert stage.bool_calls == 0
    assert source.bool_calls == 0
    assert context.bool_calls == 0


def test_stage1513_renpy_profile_text_helpers_do_not_truth_test_text_fields():
    tag = HostileText("RenPy Update")
    blank = HostileText("")

    assert updater_text.high_gate_norm((tag,)) == {"renpy update"}
    assert updater_text.sanitize_tag_part(tag) == "renpy_update"
    assert updater_text.sanitize_tag_part(blank) == "unknown"
    assert tag.bool_calls == 0
    assert blank.bool_calls == 0
