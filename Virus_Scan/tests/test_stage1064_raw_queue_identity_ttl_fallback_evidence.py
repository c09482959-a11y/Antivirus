from Virus_Scan.scheduler.queue import raw_queue_identity


def test_stage1064_queue_identity_index_ttl_fallback_records_scheduler_evidence():
    recorded = []

    def failing_float_env(name, default, minimum, maximum):
        assert name == "UMIGE_QUEUE_IDENTITY_INDEX_TTL_SEC"
        assert default == 2.0
        assert minimum == 0.25
        assert maximum is None
        raise ValueError("bad ttl")

    def record_issue(where, exc):
        recorded.append((where, type(exc).__name__, str(exc)))

    ttl = raw_queue_identity._queue_identity_index_ttl_sec(
        float_env_func=failing_float_env,
        report_issue=record_issue,
    )

    assert ttl == 2.0
    assert recorded == [("queue_identity_index_ttl_policy_unavailable", "ValueError", "bad ttl")]
