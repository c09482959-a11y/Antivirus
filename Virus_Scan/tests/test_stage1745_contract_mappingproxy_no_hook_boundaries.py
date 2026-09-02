"""Stage 1745: contract mappingproxy boundaries reject hostile backing mappings."""

from __future__ import annotations

from collections.abc import MutableMapping
from types import MappingProxyType

from Virus_Scan.contracts.analytical_evidence import analytical_correlation_ceiling, analytical_mapping_size
from Virus_Scan.contracts.api_behavior import build_api_regex
from Virus_Scan.contracts.behavior_rarity import behavior_rarity_from_flow
from Virus_Scan.contracts.call_graph_projection import api_call_graph_features
from Virus_Scan.contracts.graph_publication import api_graph_publication_edges


class HostileMapping(MutableMapping):
    touched = 0

    def __getitem__(self, key):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("mapping __getitem__ hook must not execute")

    def __iter__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("mapping __iter__ hook must not execute")

    def __len__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("mapping __len__ hook must not execute")

    def __setitem__(self, key, value):  # pragma: no cover - not used
        raise AssertionError("mapping __setitem__ hook must not execute")

    def __delitem__(self, key):  # pragma: no cover - not used
        raise AssertionError("mapping __delitem__ hook must not execute")

    def items(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("mapping items hook must not execute")

    def values(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("mapping values hook must not execute")

    def get(self, key, default=None):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("mapping get hook must not execute")


def hostile_proxy():
    HostileMapping.touched = 0
    return MappingProxyType(HostileMapping())


def test_stage1745_analytical_contracts_reject_hostile_mappingproxy_without_hooks() -> None:
    size, size_reason = analytical_mapping_size(hostile_proxy())
    assert HostileMapping.touched == 0
    assert size == 0
    assert size_reason == "unreadable_graph_features"

    ceiling = analytical_correlation_ceiling(hostile_proxy())
    assert HostileMapping.touched == 0
    assert ceiling["active_families"] == {}
    assert ceiling["capped_family_counts"] == {}
    assert ceiling["unavailable_reason"] == "non_mapping_analytical_family_counts"


def test_stage1745_behavior_rarity_rejects_hostile_mappingproxy_without_hooks() -> None:
    rarity = behavior_rarity_from_flow(("open_process",), hostile_proxy())

    assert HostileMapping.touched == 0
    assert rarity == 0.0


def test_stage1745_call_graph_contract_rejects_hostile_mappingproxy_without_hooks() -> None:
    features = api_call_graph_features(hostile_proxy())

    assert HostileMapping.touched == 0
    assert features == {"nodes": 0, "edges": 0, "density": 0.0}


def test_stage1745_graph_publication_rejects_hostile_mappingproxy_without_hooks() -> None:
    edges = api_graph_publication_edges("node", (), (), hostile_proxy())

    assert HostileMapping.touched == 0
    assert edges == (("api:graph_publication_mapping_unavailable", "api:graph_publication_iterable_unavailable", "api_sequence", 1.25),)


def test_stage1745_api_behavior_regex_rejects_hostile_mappingproxy_without_hooks() -> None:
    regex = build_api_regex(hostile_proxy())

    assert HostileMapping.touched == 0
    assert regex.pattern == r"\b()\b"


def test_stage1745_contract_mappingproxy_still_accepts_exact_dict_backing() -> None:
    proxy = MappingProxyType({"OpenProcess": 3, "CreateFile": 1})

    size, reason = analytical_mapping_size(proxy)
    assert (size, reason) == (2, None)

    graph_features = api_call_graph_features(MappingProxyType({"A": ("B", "C")}))
    assert graph_features == {"nodes": 1, "edges": 2, "density": 2 / 1.000001}
