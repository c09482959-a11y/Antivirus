"""Stage 1448 Phase 2 replay API boundary regressions."""
from __future__ import annotations

import inspect

from Virus_Scan.models import replay
from Virus_Scan.models.replay import api as replay_api
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


def test_stage1448_replay_root_does_not_publish_private_compatibility_aliases() -> None:
    assert replay.__all__ == ("persist_parent_learning_from_results",)
    assert not hasattr(replay, "result_learning_payload")
    assert not hasattr(replay, "_umige_parent_replay_result_learning")
    assert not hasattr(replay, "_umige_replay_runtime_model_observation")
    assert not hasattr(replay, "_detach_replay_payload_mapping")
    assert not hasattr(replay, "_detach_replay_payload_value")


def test_stage1448_replay_api_exposes_canonical_public_learning_and_detachment() -> None:
    assert "result_learning_payload" in replay_api.__all__
    assert "parent_replay_result_learning" in replay_api.__all__
    assert "replay_runtime_model_observation" not in replay_api.__all__
    assert not hasattr(replay_api, "replay_runtime_model_observation")
    assert "detach_replay_payload_mapping" in replay_api.__all__
    assert "detach_replay_payload_value" in replay_api.__all__
    assert "replay_learning_summary" not in replay_api.__all__
    assert not hasattr(replay_api, "replay_learning_summary")
    assert inspect.getmodule(replay_api.result_learning_payload) is replay_api
    evidence = physical_tag_evidence(("alpha", "beta"), source_stage="parent_replay")
    payload = replay_api.result_learning_payload({
        "file": "sample.rpy",
        "classification": "benign",
        "tags": ["alpha", "beta"],
        "tag_evidence": evidence.to_record(record_limit=64),
        "score": 0,
        "scan_integrity": {"allow_learning": True},
    })
    assert payload is not None
    assert payload["flow"] == ["alpha", "beta"]
