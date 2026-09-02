from __future__ import annotations

from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

import Virus_Scan.models.graph.chains as graph_chains
from Virus_Scan.models.graph.cache import cache_key


class HostileText:
    touched = 0

    def __str__(self):  # pragma: no cover - failure proves caller-owned hook ran
        type(self).touched += 1
        raise AssertionError("caller-owned __str__ executed")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __repr__ executed")

    def __format__(self, spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __format__ executed")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __bool__ executed")


class HostileStr(str):
    touched = 0

    def __new__(cls, value: str):
        return str.__new__(cls, value)

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned str subclass __str__ executed")

    def strip(self, *args, **kwargs):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned str subclass strip executed")

    def lower(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned str subclass lower executed")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned str subclass bool executed")


class HostileDepth:
    touched = 0

    def __int__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __int__ executed")

    def __index__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __index__ executed")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __bool__ executed")


def test_stage2000_graph_cache_key_rejects_unsupported_text_parts_without_hooks() -> None:
    HostileText.touched = 0

    key = cache_key(HostileText(), "node-a", HostileText())

    assert key == "graph_cache_namespace_rejected:node-a:graph_cache_key_part_rejected"
    assert HostileText.touched == 0


def test_stage2000_graph_cache_key_preserves_exact_str_subclass_without_hooks() -> None:
    HostileStr.touched = 0

    assert cache_key(HostileStr("graph_risk"), HostileStr("node-a")) == "graph_risk:node-a"
    assert HostileStr.touched == 0


def test_stage2000_chain_policy_is_not_module_reassignable_and_depth_rejects_hooks() -> None:
    HostileDepth.touched = 0

    assert not hasattr(graph_chains, "BEHAVIOR_CHAINS")
    depth = graph_chains._bounded_chain_depth(HostileDepth())

    assert depth == graph_chains.CHAIN_DEPTH_DEFAULT
    assert HostileDepth.touched == 0


def test_stage2000_chain_phase_matching_rejects_hostile_values_without_hooks() -> None:
    HostileText.touched = 0
    HostileStr.touched = 0

    score = graph_chains.score_attack_chain_presence_from_edges(
        (HostileText(), HostileStr("phase:execution"), "stage:powershell"),
        attack_graph={HostileStr("execution"): {"nodes": (HostileText(), HostileStr("powershell"))}},
    )

    assert score == 1.0
    assert HostileText.touched == 0
    assert HostileStr.touched == 0


def test_stage2000_graph_cache_chain_sources_do_not_use_unsafe_text_fallbacks() -> None:
    cache_source = read_python_file(Path("Virus_Scan/models/graph/cache.py"))
    chains_source = read_python_file(Path("Virus_Scan/models/graph/chains.py"))

    assert "safe_graph_text(namespace) + ':' + ':'.join" not in cache_source
    assert "hits.append(safe_graph_text(name))" not in chains_source
    assert "safe_graph_text(edge).lower()" not in chains_source
    assert "safe_graph_text(phase).lower()" not in chains_source
    assert "safe_graph_text(node).strip()" not in chains_source
