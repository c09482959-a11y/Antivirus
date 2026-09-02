import json

import pytest

from Virus_Scan.contracts.analytical_evidence import (
    analytical_extension_from_path,
    analytical_family_counts,
    analytical_format_oddity_snapshot,
)
from Virus_Scan.detection.scoring.calibration.analytical_bundle import (
    AnalyticalCalibrationBundleRequest,
    build_analytical_calibration_bundle as build_detection_bundle,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.runtime.analytical_calibration import (
    build_analytical_calibration_bundle as build_runtime_bundle,
)


class HostilePath:
    def __init__(self, value="sample.exe"):
        self.value = value
        self.bool_called = False

    def __bool__(self):
        self.bool_called = True
        raise AssertionError("path truthiness must not be evaluated")

    def __str__(self):
        return self.value


class HostileIterable:
    def __init__(self, values):
        self.values = tuple(values)
        self.bool_called = False

    def __bool__(self):
        self.bool_called = True
        raise AssertionError("iterable truthiness must not be evaluated")

    def __iter__(self):
        return iter(self.values)


class HostileMapping(dict):
    def __init__(self, values):
        super().__init__(values)
        self.bool_called = False

    def __bool__(self):
        self.bool_called = True
        raise AssertionError("mapping truthiness must not be evaluated")


class HostileStage:
    def __init__(self, value):
        self.value = value
        self.bool_called = False

    def __bool__(self):
        self.bool_called = True
        raise AssertionError("stage truthiness must not be evaluated")

    def __str__(self):
        return self.value


def _assert_json_safe(payload):
    json.dumps(payload, sort_keys=True, allow_nan=False)


def test_stage1498_shared_analytical_contract_does_not_probe_path_or_tag_truthiness():
    path = HostilePath("payload.exe")
    tags = HostileIterable(("packed_payload", "network_url"))

    assert analytical_extension_from_path(path) == "exe"
    families = analytical_family_counts(tags)
    oddity = analytical_format_oddity_snapshot(path=path, entropy=None, tags=tags)

    assert families["network"] > 0
    assert oddity["format"] == "exe"
    assert oddity["confidence_source"] == "tag_inferred_oddity"
    assert path.bool_called is False
    _assert_json_safe(oddity)


def test_stage1498_detection_analytical_bundle_does_not_probe_optional_input_truthiness():
    path = HostilePath("sample.exe")
    tags = normalize_tag_evidence(
        ("packed_payload", "cmd_exec"),
        source_detector="stage1498",
        source_stage="calibration",
    )
    hits = HostileIterable(("hit_a",))
    graph_features = HostileMapping({"node": 1, "edge": 2})
    prev_stage = HostileStage("prefilter")
    curr_stage = HostileStage("full_analysis")

    bundle = build_detection_bundle(
        AnalyticalCalibrationBundleRequest(
            path=path,
            tags=tags,
            
            entropy=8.5,
            prev_stage=prev_stage,
            curr_stage=curr_stage,
            graph_score=25.0,
            graph_features=graph_features,
            risk=12.0,
        )
    )

    assert bundle["sequence_probability"]["prev_stage"] == "prefilter"
    assert bundle["sequence_probability"]["curr_stage"] == "full_analysis"
    assert bundle["graph_context"]["feature_count"] == 2
    assert bundle["graph_context"]["ready"] is True
    assert path.bool_called is False
    assert hits.bool_called is False
    assert graph_features.bool_called is False
    assert prev_stage.bool_called is False
    assert curr_stage.bool_called is False
    _assert_json_safe(bundle)


def test_stage1498_detection_analytical_bundle_rejects_noncanonical_tags_without_hooks():
    tags = HostileIterable(("packed_payload",))
    with pytest.raises(TypeError, match="analytical_calibration_tag_evidence_required"):
        build_detection_bundle(
            AnalyticalCalibrationBundleRequest(path="sample.exe", tags=tags)
        )
    assert tags.bool_called is False



def test_stage1498_runtime_analytical_bundle_does_not_probe_optional_input_truthiness():
    path = HostilePath("runtime.exe")
    tags = HostileIterable(("obfus_payload",))
    hits = HostileIterable(("hit_b",))
    graph_features = HostileMapping({"node": 1})
    prev_stage = HostileStage("input")
    curr_stage = HostileStage("result")

    bundle = build_runtime_bundle(
        path=path,
        tags=tags,
        
        entropy=7.5,
        prev_stage=prev_stage,
        curr_stage=curr_stage,
        graph_score=50.0,
        graph_features=graph_features,
        risk=7.0,
    )

    assert bundle["sequence_probability"]["prev_stage"] == "input"
    assert bundle["sequence_probability"]["curr_stage"] == "result"
    assert bundle["graph_context"]["feature_count"] == 1
    assert bundle["graph_context"]["ready"] is True
    assert path.bool_called is False
    assert tags.bool_called is False
    assert hits.bool_called is False
    assert graph_features.bool_called is False
    assert prev_stage.bool_called is False
    assert curr_stage.bool_called is False
    _assert_json_safe(bundle)


def test_stage1498_unreadable_graph_features_are_explicitly_unavailable():
    class UnreadableMapping(HostileMapping):
        def keys(self):
            raise RuntimeError("graph features unavailable")

        def __iter__(self):
            raise RuntimeError("graph features unavailable")

    bundle = build_detection_bundle(
        AnalyticalCalibrationBundleRequest(
            path="sample.exe",
            tags=normalize_tag_evidence(
                ("packed_payload",), source_detector="stage1498", source_stage="calibration"
            ),
            graph_score=10.0,
            graph_features=UnreadableMapping({"hidden": 1}),
        )
    )

    assert bundle["graph_context"]["feature_count"] == 0
    assert bundle["graph_context"]["ready"] is False
    assert bundle["graph_context"]["reason"] == "unreadable_graph_features"
