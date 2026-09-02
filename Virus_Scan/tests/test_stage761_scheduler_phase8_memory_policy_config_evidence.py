from __future__ import annotations

from Virus_Scan.scheduler.timeout.inmemory_memory_policy import build_inmemory_worker_memory_policy


def test_stage761_invalid_memory_policy_env_records_immutable_timeout_config_evidence():
    policy = build_inmemory_worker_memory_policy({"UMIGE_INMEMORY_WORKER_RSS_LIMIT_MB": "not-a-number"})

    assert policy.rss_limit_mb == 2048.0
    assert policy.config_evidence
    evidence = policy.config_evidence[0]
    assert evidence["stage"] == "inmemory_worker_memory_policy_config"
    assert evidence["setting"] == "UMIGE_INMEMORY_WORKER_RSS_LIMIT_MB"
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_reproduce"] is True
    try:
        evidence["stage"] = "mutated"
    except TypeError:
        pass
    else:  # pragma: no cover
        raise AssertionError("memory policy evidence must be immutable")
