from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.contracts.graph_publication import api_graph_publication_edges
from Virus_Scan.models.clustering.common import cluster_input_sequence, cluster_mapping
from Virus_Scan.models.replay.detachment import detach_replay_payload_sequence, replay_sequence_and_errors
from Virus_Scan.models.replay_economics import replay_compress_metadata, replay_should_retain


class HostileIterable:
    touched = 0

    def __iter__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("do not iterate")


class HostileMapping(Mapping):
    touched = 0

    def __iter__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __getitem__(self, key):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("do not index")

    def __len__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("do not len")

    def get(self, key, default=None):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("do not get")

    def items(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("do not items")


class HostilePath:
    touched = 0

    def __fspath__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("do not fspath")


def test_stage1548_clustering_rejects_unknown_iterables_without_iterating() -> None:
    HostileIterable.touched = 0
    hostile = HostileIterable()

    values, reason = cluster_input_sequence(hostile, reason="cluster_unknown_sequence_rejected")

    assert values == ()
    assert reason == "cluster_unknown_sequence_rejected"
    assert HostileIterable.touched == 0


def test_stage1548_clustering_rejects_unknown_mapping_without_mapping_hooks() -> None:
    HostileMapping.touched = 0
    hostile = HostileMapping()

    mapping, reason = cluster_mapping(hostile, reason="cluster_unknown_mapping_rejected")

    assert mapping == {}
    assert reason == "cluster_unknown_mapping_rejected"
    assert HostileMapping.touched == 0


def test_stage1548_replay_sequence_rejects_unknown_iterable_without_iterating() -> None:
    HostileIterable.touched = 0
    hostile = HostileIterable()

    detached = detach_replay_payload_sequence(hostile)
    clean, errors = replay_sequence_and_errors(hostile, "payload")

    assert detached[0]["unavailable_reason"] == "unsupported_replay_payload_sequence"
    assert clean == []
    assert errors == ["payload:unsupported_replay_payload_sequence"]
    assert HostileIterable.touched == 0


def test_stage1548_replay_economics_rejects_unknown_mapping_and_fspath_without_hooks() -> None:
    HostileMapping.touched = 0
    HostilePath.touched = 0

    assert replay_should_retain(HostileMapping()) is True
    compressed_mapping = replay_compress_metadata(HostileMapping())
    compressed_path = replay_compress_metadata({"path": HostilePath()})

    assert compressed_mapping["unavailable_reason"] == "unsupported_replay_metadata_type"
    assert compressed_path["path"]["unavailable_reason"] == "unsupported_replay_metadata_type"
    assert HostileMapping.touched == 0
    assert HostilePath.touched == 0


def test_stage1548_graph_publication_rejects_unknown_iterables_and_mappings_without_hooks() -> None:
    HostileIterable.touched = 0
    HostileMapping.touched = 0

    edges = api_graph_publication_edges("node", HostileIterable(), HostileIterable(), HostileMapping())

    assert ("node", "api:graph_publication_iterable_unavailable", "api", 1.0) in edges
    assert ("node", "api_tag:graph_publication_iterable_unavailable", "api_tag", 1.5) in edges
    assert ("api:graph_publication_mapping_unavailable", "api:graph_publication_iterable_unavailable", "api_sequence", 1.25) in edges
    assert HostileIterable.touched == 0
    assert HostileMapping.touched == 0
