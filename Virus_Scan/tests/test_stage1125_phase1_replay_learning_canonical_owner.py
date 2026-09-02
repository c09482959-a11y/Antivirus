import inspect

from Virus_Scan.models import profiles, replay
from Virus_Scan.models.replay import api as replay_api
from Virus_Scan.models.api import replay_learning
from Virus_Scan.publication.api import pipeline_finalization
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


def test_parent_replay_learning_is_owned_by_models_replay_only():
    assert hasattr(replay, "persist_parent_learning_from_results")
    assert not hasattr(replay, "result_learning_payload")
    assert not hasattr(replay, "_umige_parent_replay_result_learning")
    assert not hasattr(replay, "_umige_replay_runtime_model_observation")
    assert not hasattr(profiles, "parent_replay_result_learning")
    assert not hasattr(profiles, "_umige_parent_persist_learning_from_results")
    assert not hasattr(profiles, "replay_runtime_model_observation")
    assert not hasattr(profiles, "result_learning_payload")


def test_publication_finalization_uses_public_replay_learning_contract():
    assert pipeline_finalization.model_replay_learning_contract is replay_learning
    assert pipeline_finalization.persist_parent_learning_from_results({}) == replay_learning.persist_parent_learning_from_results({})


def test_public_replay_learning_contract_delegates_to_canonical_model_owner():
    assert replay_learning.replay_model_api is replay_api
    assert replay_learning.persist_parent_learning_from_results({}) == replay_api.persist_parent_learning_from_results({})


def test_replay_uses_public_profile_learning_helpers_for_payload_flow():
    evidence = physical_tag_evidence(("alpha", "beta"), source_stage="parent_replay")
    payload = replay_api.result_learning_payload(
        {
            "file": "sample.rpy",
            "classification": "benign",
            "tags": ["alpha", "beta"],
            "tag_evidence": evidence.to_record(record_limit=64),
            "ordered_events": [],
            "behavior_flow": [],
            "score": 0,
        }
    )
    assert payload is not None
    assert payload["flow"] == ["alpha", "beta"]
    assert profiles.canonical_behavior_flow_from_sources(raw_tags=evidence) == ["alpha", "beta"]
    assert profiles.learning_verdict_is_clean("benign") is True
