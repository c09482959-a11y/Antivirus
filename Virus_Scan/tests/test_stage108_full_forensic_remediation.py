from concurrent.futures import ThreadPoolExecutor


from Virus_Scan.runtime.structured_failures import clear_failure_records, record_suppressed_failure, canonical_failure_snapshot
from Virus_Scan.runtime.structured_failures import clear_failure_records, record_suppressed_failure
from Virus_Scan.runtime.provenance import provenance_snapshot
from Virus_Scan.runtime.immutable_core import RuntimeStateReducer, RuntimeTransition
from Virus_Scan.scheduler.workers.lifecycle_boundary import SchedulerIsolationBoundary, WorkerLifecycleEvent
from Virus_Scan.runtime.provenance import reset_provenance_epoch, provenance_snapshot

def test_correlation_ids_are_replay_stable_without_pid_tid():
    clear_failure_records()
    record_suppressed_failure("json_write", ValueError("queue json write failed"), domain="persistence", context={"file":"q.json", "attempt": 1})
    a = canonical_failure_snapshot()
    clear_failure_records()
    record_suppressed_failure("json_write", ValueError("queue json write failed"), domain="persistence", context={"file":"q.json", "attempt": 1})
    b = canonical_failure_snapshot()
    assert a == b
    corr = a["records"][0]["correlation_id"]
    assert "pid" not in corr and "tid" not in corr


def test_provenance_store_is_append_only_and_canonical():
    clear_failure_records()
    record_suppressed_failure("queue_retry", RuntimeError("claim failed"), domain="scheduler", context={"queue_identity":"a", "retry_generation": 2})
    record_suppressed_failure("queue_retry", RuntimeError("claim failed"), domain="scheduler", context={"queue_identity":"a", "retry_generation": 2})
    snap = provenance_snapshot(canonical=True)
    assert len(snap["events"]) >= 2
    assert all("runtime_epoch" not in (e.get("provenance") or {}) for e in snap["events"])
    assert any(e.get("event_type") == "failure_recorded" for e in snap["events"])


def test_immutable_runtime_reducer_rejects_cross_owner_mutation():
    r = RuntimeStateReducer(owner="queue")
    s1 = r.apply(RuntimeTransition(owner="queue", action="set", key="job", value={"state":"queued"}))
    assert s1.snapshot()["job"] == {"state":"queued"}
    assert s1.version == 1
    try:
        r.apply(RuntimeTransition(owner="scanner", action="set", key="job", value="bad"))
    except PermissionError:
        pass
    else:
        raise AssertionError("cross-owner mutation was accepted")
    assert r.current().snapshot()["job"] == {"state":"queued"}


def test_scheduler_isolation_rejects_invalid_or_stale_transitions():
    s = SchedulerIsolationBoundary(scheduler_id="test")
    s.transition(WorkerLifecycleEvent("w1", "q1", "new", "queued"))
    s.transition(WorkerLifecycleEvent("w1", "q1", "queued", "claimed"))
    assert s.state_of("q1") == "claimed"
    try:
        s.transition(WorkerLifecycleEvent("w1", "q1", "queued", "running"))
    except RuntimeError as exc:
        assert "state mismatch" in str(exc)
    else:
        raise AssertionError("stale scheduler transition was accepted")
    try:
        s.transition(WorkerLifecycleEvent("w1", "q1", "claimed", "completed"))
    except RuntimeError as exc:
        assert "invalid scheduler transition" in str(exc)
    else:
        raise AssertionError("invalid scheduler transition was accepted")


def test_scheduler_isolation_concurrent_transitions_are_attributable():
    reset_provenance_epoch()
    s = SchedulerIsolationBoundary(scheduler_id="concurrent")
    def run(i):
        q = f"q{i}"
        s.transition(WorkerLifecycleEvent(f"w{i}", q, "new", "queued"))
        s.transition(WorkerLifecycleEvent(f"w{i}", q, "queued", "claimed"))
        s.transition(WorkerLifecycleEvent(f"w{i}", q, "claimed", "running"))
        s.transition(WorkerLifecycleEvent(f"w{i}", q, "running", "completed"))

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(run, range(64)))
    snap = s.snapshot()
    assert all(v == "completed" for v in snap["states"].values())
    prov = provenance_snapshot(canonical=True)["events"]
    assert any(e.get("event_type") == "worker_lifecycle" for e in prov)
