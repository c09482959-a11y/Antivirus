from Virus_Scan.tests.support.static_inventory import read_python_file

from types import MappingProxyType
from pathlib import Path

import pytest

from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.scoring.full_analysis import layered_score
from Virus_Scan.detection.scoring.weighting import static_layer
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence



def test_layered_score_policy_constants_are_immutable_snapshots():
    assert isinstance(layered_score._WEIGHTS, MappingProxyType)
    assert isinstance(static_layer._STATIC_POINT_ROWS, tuple)
    assert isinstance(static_layer._STATIC_POINTS, MappingProxyType)
    assert isinstance(layered_score._GRAPH_TAGS, frozenset)
    assert isinstance(layered_score._INTEL_TAGS, frozenset)


def test_layered_score_weights_cannot_be_mutated_by_callers():
    with pytest.raises(TypeError):
        layered_score._WEIGHTS["quick"] = 0.0


def test_layered_score_static_anchor_behavior_is_preserved():
    tag_evidence = physical_tag_evidence(
        ("powershell_exec", "encoded_powershell"),
        source_detector="stage1121",
        source_stage="layered_score",
    )
    chain_evidence = evaluate_chain_evidence(tags=tag_evidence)
    result = layered_score.compute_layered_detection(
        "sample.ps1",
        tag_evidence,
        chain_evidence,
        yara_hits=[],
        curr_stage="ps1",
    )

    assert result["layers"]["quick"]["score"] == 0.0
    assert any(
        reason.startswith("chain_bonus:anchor:encoded_powershell")
        for reason in result["reasons"]
    )


class HostileLayerMapping:
    touched_values = 0
    touched_items = 0
    touched_getitem = 0

    def values(self):
        type(self).touched_values += 1
        raise RuntimeError("hostile layer values must not execute")

    def items(self):
        type(self).touched_items += 1
        raise RuntimeError("hostile layer items must not execute")

    def __getitem__(self, _key):
        type(self).touched_getitem += 1
        raise RuntimeError("hostile layer lookup must not execute")


def test_layered_score_rejects_unknown_layer_mapping_without_hooks():
    HostileLayerMapping.touched_values = 0
    HostileLayerMapping.touched_items = 0
    HostileLayerMapping.touched_getitem = 0

    score, active_layers = layered_score._weighted_score(HostileLayerMapping())
    reasons = layered_score._layer_reasons(HostileLayerMapping())

    assert score == 0.0
    assert active_layers == 0
    assert reasons == []
    assert HostileLayerMapping.touched_values == 0
    assert HostileLayerMapping.touched_items == 0
    assert HostileLayerMapping.touched_getitem == 0


def test_layered_score_source_avoids_hookable_layer_mapping_iteration():
    source = read_python_file(Path("Virus_Scan/detection/scoring/full_analysis/layered_score.py"))
    forbidden = (
        'return safe_clamp(score, 0.0, 100.0), sorted(set(hits))',
        'return safe_clamp(score, 0.0, 100.0), sorted(set(hits)), stable_curr_stage, previous',
        'return safe_clamp(score, 0.0, 100.0), hits',
        'score = sum(layers[name]["score"] * weight for name, weight in _WEIGHTS.items())',
        'active_layers = sum(1 for layer in layers.values() if layer["score"] >= 20.0)',
        'has_injection_sequence = bool("injection_api_chain" in tagset',
        'score = safe_clamp(floor_score, 0.0, 100.0)',
        'for layer in layers.values():',
    )
    assert [snippet for snippet in forbidden if snippet in source] == []
