from __future__ import annotations
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision

from collections.abc import Mapping

import pytest

from Virus_Scan.models.api import clustering_contracts as clustering_api
from Virus_Scan.models.api import graph_contracts as graph_api
from Virus_Scan.models.api import profile_contracts as profile_api
from Virus_Scan.models.api import profile_learning_contracts as profile_learning_api
from Virus_Scan.models.api import profile_retention_contracts as profile_retention_api


class _BadText:
    def __str__(self):
        raise RuntimeError("bad public model key text")

    def __repr__(self):
        raise RuntimeError("bad public model key repr")


class _HostileMapping(Mapping):
    def __iter__(self):
        return iter((_BadText(),))

    def __len__(self):
        return 1

    def __getitem__(self, key):
        return {_BadText(): {_BadText()}}

    def keys(self):
        return (_BadText(),)


def _hostile_payload():
    return {_BadText(): {_BadText(): {_BadText()}}}


def _assert_immutable_public_payload(value):
    assert isinstance(value, Mapping)
    assert "<unreadable_mapping_key_0>" in value
    with pytest.raises(TypeError):
        value["mutation"] = "must fail"


def test_stage1409_graph_public_contract_freezes_hostile_mapping_keys():
    evidence = graph_api._immutable_graph_value(_hostile_payload())
    assert isinstance(evidence, Mapping)

    _assert_immutable_public_payload(evidence)


def test_stage1409_cluster_assignment_public_contract_returns_degraded_for_invalid_vector():
    evidence = clustering_api.assign_cluster_with_context_tags("node", _BadText(), tags=("tag",), learning_decision=accepted_learning_decision(target_names=("clustering",)))

    assert isinstance(evidence, Mapping)
    assert evidence["ready"] is False
    assert evidence["degraded"] is True
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    with pytest.raises(TypeError):
        evidence["mutation"] = "must fail"


def test_stage1409_cluster_public_contract_freezes_hostile_mapping_keys():
    evidence = clustering_api._immutable_cluster_value(_hostile_payload())
    assert isinstance(evidence, Mapping)

    _assert_immutable_public_payload(evidence)


def test_stage1409_profile_public_contract_freezes_hostile_mapping_keys():
    evidence = profile_api._immutable_profile_value(_hostile_payload())
    assert isinstance(evidence, Mapping)

    _assert_immutable_public_payload(evidence)


def test_stage1409_profile_learning_public_contract_freezes_hostile_owner_result():
    evidence = profile_learning_api._immutable_profile_learning_value(_hostile_payload())
    assert isinstance(evidence, Mapping)

    _assert_immutable_public_payload(evidence)


def test_stage1409_profile_retention_public_contract_freezes_hostile_owner_result():
    evidence = profile_retention_api._immutable_retention_value(_hostile_payload())
    assert isinstance(evidence, Mapping)

    _assert_immutable_public_payload(evidence)


def test_stage1409_profile_retention_public_contract_detaches_hostile_input_mapping():
    evidence = profile_retention_api.prune_engine_profile_for_retention(_HostileMapping())

    assert isinstance(evidence, Mapping)
    assert "<unreadable_mapping_key_0>" in evidence or evidence.get("degraded") is True
