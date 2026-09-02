from pathlib import Path

from Virus_Scan.scheduler.queue.claim_sidecar_policy import active_claim_is_protected


def test_stage1065_active_claim_invalid_heartbeat_reports_with_claim_path(tmp_path: Path):
    claim_path = tmp_path / "active" / "job.json"
    claim_path.parent.mkdir()
    claim_path.write_text("{}", encoding="utf-8")
    reports = []

    result = active_claim_is_protected(
        claim_path,
        job={"queue_info": {"heartbeat_time": "not-a-float", "worker_pid": 777}},
        now=1000.0,
        grace=15.0,
        path_age=lambda _path, _now: 500.0,
        read_json=lambda _path, default=None: default,
        merge_claim_meta=lambda _path, payload: payload,
        pid_is_alive=lambda _pid: False,
        queue_now=lambda: 1000.0,
        report=lambda where, exc, **kwargs: reports.append((where, type(exc).__name__, kwargs)),
    )

    assert result is False
    assert reports[0] == (
        "queue_active_claim_heartbeat_invalid",
        "ValueError",
        {"fatal": False, "extra": {"claim": str(claim_path)}},
    )
    assert reports[1][0] == "queue_active_claim_unprotected_stale_worker"
    assert reports[1][1] == "RuntimeError"
    assert reports[1][2]["fatal"] is False
    unprotected = reports[1][2]["extra"]
    assert unprotected["claim"] == str(claim_path)
    assert unprotected["pid_alive"] is False
    assert unprotected["pid_type"] == "int"
    assert unprotected["heartbeat_available"] is False
    assert unprotected["heartbeat_age"] == 500.0
    assert unprotected["active_grace"] == 15.0
    assert unprotected["final_json_must_record"] is True
    assert unprotected["checkpoint_must_record"] is True
    assert unprotected["replay_must_record"] is True


def test_stage2184_active_claim_stale_worker_denial_is_replayable(tmp_path: Path):
    claim_path = tmp_path / "active" / "job.json"
    claim_path.parent.mkdir()
    claim_path.write_text("{}", encoding="utf-8")
    reports = []

    result = active_claim_is_protected(
        claim_path,
        job={"queue_info": {"heartbeat_time": 100.0, "worker_pid": 777}},
        now=1000.0,
        grace=15.0,
        path_age=lambda _path, _now: 900.0,
        read_json=lambda _path, default=None: default,
        merge_claim_meta=lambda _path, payload: payload,
        pid_is_alive=lambda _pid: False,
        queue_now=lambda: 1000.0,
        report=lambda where, exc, **kwargs: reports.append((where, type(exc).__name__, kwargs)),
    )

    assert result is False
    assert len(reports) == 1
    assert reports[0][0] == "queue_active_claim_unprotected_stale_worker"
    assert reports[0][1] == "RuntimeError"
    extra = reports[0][2]["extra"]
    assert extra["claim"] == str(claim_path)
    assert extra["pid_alive"] is False
    assert extra["pid_type"] == "int"
    assert extra["heartbeat_available"] is True
    assert extra["heartbeat_age"] == 900.0
    assert extra["active_grace"] == 15.0
    assert extra["final_json_must_record"] is True
    assert extra["checkpoint_must_record"] is True
    assert extra["replay_must_record"] is True
