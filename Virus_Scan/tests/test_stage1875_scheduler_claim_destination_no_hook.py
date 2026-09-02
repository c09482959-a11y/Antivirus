import json
from pathlib import Path

from Virus_Scan.scheduler.queue import claim as matching_claim
from Virus_Scan.scheduler.queue import claim_destination


class HostileComponent:
    hits = 0

    __slots__ = ()

    @classmethod
    def touch(cls):
        cls.hits += 1
        raise AssertionError("caller-owned hook executed")

    def __str__(self):
        return type(self).touch()

    def __repr__(self):
        return type(self).touch()

    def __format__(self, _spec):
        return type(self).touch()

    def __bool__(self):
        return type(self).touch()

    def __iter__(self):
        return type(self).touch()

    def __fspath__(self):
        return type(self).touch()


def _write_job(queue_dir: Path, name: str, payload: dict) -> Path:
    pending, active, done, failed = matching_claim._queue_job_dirs(queue_dir)
    for directory in (pending, active, done, failed):
        directory.mkdir(parents=True, exist_ok=True)
    path = pending / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _job_payload(tmp_path: Path, file_name: str = "sample.bin") -> dict:
    target = tmp_path / file_name
    target.write_bytes(b"payload")
    return {"file": str(target), "job_type": "file", "queue_file_id": "id-" + file_name}


def test_claim_destination_name_rejects_hostile_components_without_hooks():
    HostileComponent.hits = 0
    seen = []

    name = claim_destination.claim_destination_name(
        HostileComponent(),
        HostileComponent(),
        worker_pid=123,
        record_suppressed=lambda where, exc, **kwargs: seen.append((where, kwargs)),
    )

    assert HostileComponent.hits == 0
    assert name == "worker_123_pending_job_rejected.json"
    assert seen
    assert seen[0][0] == "queue_claim_destination_component_rejected"
    extra = seen[0][1]["extra"]
    assert extra["queue_claim_destination_component_rejected"] is True
    assert {issue["field_name"] for issue in extra["component_issues"]} == {"worker_id", "pending_name"}
    assert all(issue["final_json_must_record"] is True for issue in extra["component_issues"])


def test_matching_claim_rejects_hostile_worker_id_before_destination_format_hooks(tmp_path):
    HostileComponent.hits = 0
    queue_dir = tmp_path / "q"
    _write_job(queue_dir, "000001.json", _job_payload(tmp_path, "matching.bin"))
    seen = []

    job, claim_path = matching_claim.claim_process_queue_job_matching(
        queue_dir,
        lambda job: True,
        worker_id=HostileComponent(),
        enqueue_guard=lambda *args, **kwargs: True,
        claim_sidecar_from_job=lambda *args, **kwargs: True,
        duplicate_live_guard=lambda *args, **kwargs: True,
        merge_claim_meta_into_job=lambda dst, job: job,
        record_suppressed=lambda where, exc, **kwargs: seen.append((where, kwargs)),
    )

    assert HostileComponent.hits == 0
    assert job is not None
    assert claim_path is not None
    assert claim_path.name.endswith("_000001.json")
    assert claim_path.name.startswith("worker_")
    assert "HostileComponent" not in claim_path.name
    assert any(where == "queue_claim_destination_component_rejected" for where, _ in seen)


def test_file_claim_rejects_hostile_worker_id_before_destination_format_hooks(tmp_path):
    HostileComponent.hits = 0
    queue_dir = tmp_path / "q"
    _write_job(queue_dir, "000002.json", _job_payload(tmp_path, "file.bin"))
    seen = []

    job, claim_path = matching_claim.claim_process_queue_job(
        queue_dir,
        worker_id=HostileComponent(),
        duplicate_live_guard=lambda *args, **kwargs: True,
        merge_claim_meta_into_job=lambda dst, job: job,
        record_suppressed=lambda where, exc, **kwargs: seen.append((where, kwargs)),
    )

    assert HostileComponent.hits == 0
    assert job is not None
    assert claim_path is not None
    assert claim_path.name.endswith("_000002.json")
    assert claim_path.name.startswith("worker_")
    assert "HostileComponent" not in claim_path.name
    assert any(where == "queue_claim_destination_component_rejected" for where, _ in seen)


def test_claim_destination_source_has_no_worker_fstring_hook_path():
    claim_source = Path(matching_claim.__file__).read_text(encoding="utf-8")
    file_claim_source = Path(matching_claim._execute_process_queue_file_claim.__globals__["__file__"]).read_text(encoding="utf-8")
    forbidden = 'f"{worker_id}_{os.getpid()}_{name}"'
    assert forbidden not in claim_source
    assert forbidden not in file_claim_source
    assert "claim_destination_name" in claim_source
    assert "claim_destination_name" in file_claim_source
