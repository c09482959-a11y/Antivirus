from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


from Virus_Scan.runtime.transactional_state import TransactionalRuntimeJournal, RuntimeTransaction
from Virus_Scan.runtime.immutable_core import RuntimeTransition
from Virus_Scan.contracts.runtime_contracts import RuntimeContractRegistry, QueueOwnershipContract, RuntimeContractViolation
from Virus_Scan.runtime.provenance_graph import ProvenanceGraphStore, ProvenanceGraphEvent
from Virus_Scan.scheduler.workers.lifecycle_boundary import SchedulerIsolationBoundary, WorkerLifecycleEvent
from Virus_Scan.contracts.runtime_contracts import RuntimeContractRegistry, QueueOwnershipContract
from Virus_Scan.runtime.entropy_governance import audit_entropy

def test_transactional_journal_is_replay_deterministic_and_owner_scoped():
    j = TransactionalRuntimeJournal(owner="queue")
    tx = RuntimeTransaction.build(owner="queue", transitions=[
        RuntimeTransition(owner="queue", action="set", key="job:a", value={"state":"queued"}),
        RuntimeTransition(owner="queue", action="append", key="events", value="queued:a"),
    ], reason="enqueue")
    cp = j.apply(tx)
    assert cp.version == 2
    assert cp.values["job:a"] == {"state":"queued"}
    replayed = TransactionalRuntimeJournal.replay("queue", j.journal_snapshot())
    assert replayed.canonical() == cp.canonical()
    try:
        RuntimeTransaction.build(owner="queue", transitions=[RuntimeTransition(owner="scanner", action="set", key="x", value=1)])
    except PermissionError:
        pass
    else:
        raise AssertionError("cross-owner transaction accepted")


def test_runtime_contract_registry_rejects_queue_owner_conflict():
    reg = RuntimeContractRegistry()
    c = reg.register_queue(QueueOwnershipContract(queue_id="q1", owner_domain="scheduler", scheduler_id="s1", generation=1))
    assert reg.require_owner("q1", "scheduler").contract_id == c.contract_id
    try:
        reg.register_queue(QueueOwnershipContract(queue_id="q1", owner_domain="scanner", scheduler_id="s1", generation=1))
    except RuntimeContractViolation:
        pass
    else:
        raise AssertionError("conflicting queue owner was accepted")


def test_provenance_graph_detects_missing_parent_and_is_stable():
    g = ProvenanceGraphStore()
    a = g.append(ProvenanceGraphEvent.build(event_type="queue_claim", subsystem="scheduler", payload={"queue":"q"}))
    b = g.append(ProvenanceGraphEvent.build(event_type="worker_fail", subsystem="worker", payload={"queue":"q", "time":123}, parent_ids=[a.event_id]))
    assert g.validate()["ok"] is True
    snap1 = g.canonical_snapshot()
    g.append(ProvenanceGraphEvent.build(event_type="orphan", subsystem="replay", parent_ids=["missing-parent"]))
    assert g.validate()["ok"] is False
    snap2 = g.canonical_snapshot()
    assert snap1["graph_digest"] != snap2["graph_digest"]
    assert b.event_id in {e["event_id"] for e in snap2["events"]}


def test_scheduler_isolation_and_contracts_survive_concurrent_lifecycle():
    reg = RuntimeContractRegistry()
    boundary = SchedulerIsolationBoundary(scheduler_id="stage109")
    def run(i):
        q = f"q{i}"
        reg.register_queue(QueueOwnershipContract(queue_id=q, owner_domain="scheduler", scheduler_id="stage109", generation=i))
        reg.require_owner(q, "scheduler")
        boundary.transition(WorkerLifecycleEvent(f"w{i}", q, "new", "queued"))
        boundary.transition(WorkerLifecycleEvent(f"w{i}", q, "queued", "claimed"))
        boundary.transition(WorkerLifecycleEvent(f"w{i}", q, "claimed", "running"))
        boundary.transition(WorkerLifecycleEvent(f"w{i}", q, "running", "completed"))

    with ThreadPoolExecutor(max_workers=10) as executor:
        list(executor.map(run, range(100)))
    assert all(state == "completed" for state in boundary.snapshot()["states"].values())


def test_entropy_governance_audit_reports_hotspots():
    root = Path(__file__).resolve().parents[1]
    report = audit_entropy(root)
    assert report["totals"]["modules"] > 100
    assert "broad_handlers" in report["totals"]
    assert report["hotspots"]


def test_stage1824_entropy_audit_skips_nested_tests_tree(tmp_path):
    package_root = tmp_path / "pkg"
    source_dir = package_root / "runtime"
    tests_dir = package_root / "tests"
    source_dir.mkdir(parents=True)
    tests_dir.mkdir(parents=True)
    (source_dir / "owner.py").write_text("import os\nclass RuntimeOwner:\n    pass\n", encoding="utf-8")
    (tests_dir / "test_generated_noise.py").write_text("import time\nclass TestNoise:\n    pass\n", encoding="utf-8")

    report = audit_entropy(package_root)
    paths = {entry["path"] for entry in report["hotspots"]}

    assert "runtime/owner.py" in paths
    assert "tests/test_generated_noise.py" not in paths
