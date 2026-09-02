import json
from pathlib import Path

from Virus_Scan.core.paths import _queue_claim_meta_path
from Virus_Scan.runtime.structured_failures import clear_failure_records, failure_snapshot
from Virus_Scan.scheduler.queue import claim_heartbeat


class HostileScalar:
    def __init__(self):
        self.hits = []

    def __str__(self):  # failure path if called
        self.hits.append("str")
        raise AssertionError("__str__ must not execute")

    def __repr__(self):  # failure path if called
        self.hits.append("repr")
        raise AssertionError("__repr__ must not execute")

    def __format__(self, spec):  # failure path if called
        self.hits.append("format")
        raise AssertionError("__format__ must not execute")

    def __bool__(self):  # failure path if called
        self.hits.append("bool")
        raise AssertionError("__bool__ must not execute")

    def __iter__(self):  # failure path if called
        self.hits.append("iter")
        raise AssertionError("__iter__ must not execute")

    def __float__(self):  # failure path if called
        self.hits.append("float")
        raise AssertionError("__float__ must not execute")

    def __int__(self):  # failure path if called
        self.hits.append("int")
        raise AssertionError("__int__ must not execute")


class HostilePath(HostileScalar):
    def __fspath__(self):  # failure path if called
        self.hits.append("fspath")
        raise AssertionError("__fspath__ must not execute")

    @property
    def name(self):  # failure path if called
        self.hits.append("name")
        raise AssertionError("path.name must not execute")



def test_claim_heartbeat_rejects_hostile_worker_id_without_hooks(tmp_path: Path):
    claim = tmp_path / "active" / "job.json"
    claim.parent.mkdir(parents=True)
    claim.write_text(json.dumps({"file": "x"}), encoding="utf-8")
    hostile_worker = HostileScalar()
    hostile_claimed_time = HostileScalar()

    assert claim_heartbeat._umige_update_claim_heartbeat(
        claim,
        {"file": "x", "queue_info": {"claimed_time": hostile_claimed_time}},
        worker_id=hostile_worker,
    ) is True

    meta = json.loads(_queue_claim_meta_path(claim).read_text(encoding="utf-8"))
    queue_info = meta["queue_info"]
    assert queue_info["worker_id"] == "queue_claim_worker_id_rejected"
    assert queue_info["worker_id_issue"] == "queue_claim_worker_id_rejected"
    assert queue_info["worker_id_type"] == "HostileScalar"
    assert type(queue_info["progress_time"]) is float
    assert hostile_worker.hits == []
    assert hostile_claimed_time.hits == []



def test_claim_heartbeat_invalid_path_fails_closed_with_evidence_without_hooks():
    clear_failure_records()
    hostile_path = HostilePath()
    hostile_worker = HostileScalar()

    assert claim_heartbeat._umige_update_claim_heartbeat(hostile_path, worker_id=hostile_worker) is False

    assert hostile_path.hits == []
    assert hostile_worker.hits == []
    wheres = {record.get("where") for record in failure_snapshot().get("records", [])}
    assert "queue_claim_heartbeat_failed" in wheres



def test_claim_heartbeat_cleanup_failure_is_not_a_silent_false_sentinel():
    clear_failure_records()
    hostile_path = HostilePath()

    assert claim_heartbeat._umige_remove_claim_heartbeat_meta(hostile_path) is False

    assert hostile_path.hits == []
    wheres = {record.get("where") for record in failure_snapshot().get("records", [])}
    assert "queue_claim_meta_cleanup_failed" in wheres



def test_claim_heartbeat_source_has_no_false_sentinel_or_worker_materialization_route():
    source = Path(claim_heartbeat.__file__).read_text(encoding="utf-8")
    forbidden = (
        "return False",
        "str(worker_id",
        "worker_id or",
        "str(exc)",
    )
    for token in forbidden:
        assert token not in source
