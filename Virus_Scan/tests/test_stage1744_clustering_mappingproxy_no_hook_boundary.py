"""Stage 1744: clustering mapping boundaries reject hostile mappingproxy backing."""

from __future__ import annotations

from collections.abc import MutableMapping
from types import MappingProxyType

from Virus_Scan.models.clustering.common import cluster_mapping, dominant_engine_context


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


def test_stage1744_cluster_mapping_rejects_mappingproxy_backed_by_hostile_mapping_without_hooks() -> None:
    HostileMapping.touched = 0
    result, reason = cluster_mapping(
        MappingProxyType(HostileMapping()),
        reason="cluster_mapping_proxy_backing_rejected",
    )

    assert HostileMapping.touched == 0
    assert result == {}
    assert reason == "cluster_mapping_proxy_backing_rejected"


def test_stage1744_dominant_engine_context_rejects_hostile_mappingproxy_without_hooks() -> None:
    HostileMapping.touched = 0
    engine = dominant_engine_context(
        MappingProxyType(HostileMapping()),
        default="renpy",
    )

    assert HostileMapping.touched == 0
    assert engine == "renpy"


def test_stage1744_cluster_mapping_still_accepts_exact_dict_backed_mappingproxy() -> None:
    result, reason = cluster_mapping(MappingProxyType({"renpy": 0.75}), reason="unavailable")

    assert result == {"renpy": 0.75}
    assert reason is None
