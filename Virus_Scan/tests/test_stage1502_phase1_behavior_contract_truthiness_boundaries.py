from __future__ import annotations

from pathlib import Path

from Virus_Scan.contracts.api_behavior import api_to_timeline_tag, map_api_to_group
from Virus_Scan.contracts.behavior_rarity import behavior_rarity_from_flow
from Virus_Scan.contracts.call_graph_projection import api_call_graph_features, immutable_api_call_graph
from Virus_Scan.detection.scoring.weighting.behavior_learning import tag_rarity_score


class HostileText:
    def __init__(self, text: str):
        self.text = text
        self.bool_calls = 0

    def __bool__(self):  # pragma: no cover - must not be invoked
        self.bool_calls += 1
        raise AssertionError("caller-owned text truthiness was probed")

    def __str__(self):
        return self.text


class HostileIterable:
    def __init__(self, values):
        self.values = tuple(values)
        self.bool_calls = 0

    def __bool__(self):  # pragma: no cover - must not be invoked
        self.bool_calls += 1
        raise AssertionError("caller-owned iterable truthiness was probed")

    def __iter__(self):
        return iter(self.values)


class HostileMapping(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bool_calls = 0

    def __bool__(self):  # pragma: no cover - must not be invoked
        self.bool_calls += 1
        raise AssertionError("caller-owned mapping truthiness was probed")



def test_stage1502_api_behavior_does_not_probe_api_name_truthiness():
    api = HostileText("CreateProcessA")

    assert map_api_to_group(api) == "process_execution"
    assert api_to_timeline_tag(api) == "process_exec"
    assert api.bool_calls == 0



def test_stage1502_api_call_graph_does_not_probe_sequence_or_item_truthiness():
    left = HostileText("CreateProcessA")
    right = HostileText("WriteProcessMemory")
    sequence = HostileIterable((left, right, HostileText("CreateRemoteThread")))

    graph = immutable_api_call_graph(sequence)

    assert tuple(graph["CreateProcessA"]) == ("WriteProcessMemory",)
    assert tuple(graph["WriteProcessMemory"]) == ("CreateRemoteThread",)
    assert sequence.bool_calls == 0
    assert left.bool_calls == 0
    assert right.bool_calls == 0



def test_stage1502_api_call_graph_features_do_not_probe_mapping_or_values_truthiness():
    edges = HostileIterable(("B", "C"))
    graph = HostileMapping({"A": edges})

    features = api_call_graph_features(graph)

    assert features["nodes"] == 1
    assert features["edges"] == 2
    assert graph.bool_calls == 0
    assert edges.bool_calls == 0



def test_stage1502_behavior_rarity_and_scoring_do_not_probe_flow_or_baseline_truthiness():
    flow = HostileIterable(("decode", "exec"))
    baseline = HostileMapping({"decode": 12, "exec": 18})

    rarity = behavior_rarity_from_flow(flow, baseline, min_support=1)
    score = tag_rarity_score(flow, baseline)

    assert 0.0 <= rarity <= 1.0
    assert 0.0 <= score <= 1.0
    assert flow.bool_calls == 0
    assert baseline.bool_calls == 0



def test_stage1502_repaired_behavior_contract_sources_do_not_contain_targeted_or_fallbacks():
    roots = [
        Path("Virus_Scan/contracts/api_behavior.py"),
        Path("Virus_Scan/contracts/call_graph_projection.py"),
        Path("Virus_Scan/contracts/behavior_rarity.py"),
        Path("Virus_Scan/detection/scoring/weighting/behavior_learning.py"),
    ]
    forbidden = (
        "api or ''",
        'api or ""',
        "api_sequence or ()",
        "item or ''",
        'item or ""',
        "call_graph or {}",
        "value or ()",
        "flow or ()",
        "baseline or {}",
        "tags or []",
    )
    for path in roots:
        source = path.read_text(encoding="utf-8")
        for snippet in forbidden:
            assert snippet not in source, f"{snippet!r} still present in {path}"
