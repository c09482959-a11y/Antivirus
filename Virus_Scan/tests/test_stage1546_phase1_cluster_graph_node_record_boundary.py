from __future__ import annotations

import json
from types import MappingProxyType

import pytest

from Virus_Scan.models.clustering.state import ClusterGraphNodeRecord, cluster_graph_node_snapshot
from Virus_Scan.runtime.graph_state import (
    add_graph_edge_owned,
    ensure_graph_node_owned,
    reset_graph_state,
    update_graph_node_owned,
)
from Virus_Scan.tests.support.graph_corruption import clear_graph_node_for_test


class HostileMetadata:
    touched = 0

    def __str__(self):  # pragma: no cover - failure proves hostile hook use
        type(self).touched += 1
        raise RuntimeError("do not stringify hostile metadata")

    def __repr__(self):  # pragma: no cover - failure proves hostile hook use
        type(self).touched += 1
        raise RuntimeError("do not repr hostile metadata")


def test_stage1546_cluster_graph_record_distinguishes_missing_node() -> None:
    reset_graph_state()
    try:
        record = cluster_graph_node_snapshot('stage1546_missing.exe')
        assert isinstance(record, ClusterGraphNodeRecord)
        assert record.available is True
        assert record.present is False
        assert record.empty is False
        assert record.corrupt is False
        assert record.unavailable_reason == 'graph_node_missing'
        assert record.risk is None
        assert record.tags == ()
        assert record.edges == ()
    finally:
        reset_graph_state()


def test_stage1546_cluster_graph_record_distinguishes_present_empty_node() -> None:
    reset_graph_state()
    try:
        ensure_graph_node_owned('stage1546_empty.exe')
        clear_graph_node_for_test('stage1546_empty.exe')
        record = cluster_graph_node_snapshot('stage1546_empty.exe')
        assert record.available is True
        assert record.present is True
        assert record.empty is True
        assert record.corrupt is False
        assert record.unavailable_reason == ''
        assert record.risk is None
        assert record.tags == ()
        assert record.edges == ()
    finally:
        reset_graph_state()


def test_stage1546_cluster_graph_record_exposes_immutable_present_evidence() -> None:
    reset_graph_state()
    try:
        update_graph_node_owned('stage1546_present.exe', risk=77.0, tags={'process_injection'})
        add_graph_edge_owned('stage1546_present.exe', 'stage1546_peer.exe', edge_type='method_call', weight=1.0)
        update_graph_node_owned('stage1546_present.exe', last_seen=12.0)
        record = cluster_graph_node_snapshot('stage1546_present.exe')
        assert record.available is True
        assert record.present is True
        assert record.empty is False
        assert record.corrupt is False
        assert record.risk == 77.0
        assert 'process_injection' in record.tags
        assert 'stage1546_peer.exe' in record.edges
        assert record.metadata.get('last_seen') == 12.0
        json.dumps(record.to_json(), sort_keys=True)
        with pytest.raises(TypeError):
            record.metadata['last_seen'] = 99.0
    finally:
        reset_graph_state()


def test_stage1546_cluster_graph_record_to_json_recurses_nested_immutable_metadata() -> None:
    record = ClusterGraphNodeRecord(
        node_key='stage1546_nested_metadata.exe',
        available=True,
        present=True,
        empty=False,
        corrupt=False,
        unavailable_reason='',
        risk=1.0,
        tags=(),
        edges=(),
        metadata=MappingProxyType({
            'nested': MappingProxyType({
                'frozen_set': frozenset({'beta', 'alpha'}),
                'inner': MappingProxyType({'count': 2}),
            }),
        }),
    )

    materialized = record.to_json()

    json.dumps(materialized, sort_keys=True)
    assert materialized['metadata']['nested']['inner']['count'] == 2
    assert materialized['metadata']['nested']['frozen_set'] == ['alpha', 'beta']


def test_stage1546_cluster_graph_record_to_json_rejects_hostile_metadata_without_touching_hooks() -> None:
    HostileMetadata.touched = 0
    record = ClusterGraphNodeRecord(
        node_key='stage1546_hostile_metadata.exe',
        available=True,
        present=True,
        empty=False,
        corrupt=False,
        unavailable_reason='',
        risk=0.0,
        tags=(),
        edges=(),
        metadata=MappingProxyType({'hostile': HostileMetadata()}),
    )

    materialized = record.to_json()

    json.dumps(materialized, sort_keys=True)
    assert HostileMetadata.touched == 0
    assert materialized['metadata']['hostile']['value'] is None
    assert materialized['metadata']['hostile']['unavailable_reason'] == 'non_materializable_cluster_graph_value'
