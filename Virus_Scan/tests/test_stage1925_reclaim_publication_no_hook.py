from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import json
from pathlib import Path

from Virus_Scan.scheduler.queue.reclaim_publication import _publish_reclaimed_pending_job


class HostileValue:
    touched = 0

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile bool hook touched")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile str hook touched")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile repr hook touched")

    def __fspath__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile fspath hook touched")


class HostileMapping(dict):
    def get(self, *_args, **_kwargs):  # pragma: no cover
        HostileValue.touched += 1
        raise AssertionError("hostile mapping get touched")

    def items(self):  # pragma: no cover
        HostileValue.touched += 1
        raise AssertionError("hostile mapping items touched")

    def __iter__(self):  # pragma: no cover
        HostileValue.touched += 1
        raise AssertionError("hostile mapping iter touched")

    def __bool__(self):  # pragma: no cover
        HostileValue.touched += 1
        raise AssertionError("hostile mapping bool touched")


def test_stage1925_reclaim_publication_materializes_failure_paths_without_source_or_job_hooks(tmp_path: Path) -> None:
    HostileValue.touched = 0
    pending_path = tmp_path / "pending.json"
    pending_path.write_text("{}", encoding="utf-8")
    evidence = []
    suppressed = []

    result = _publish_reclaimed_pending_job(
        tmp_path,
        pending_path,
        HostileMapping(file=HostileValue()),
        source_path=HostileValue(),
        evidence_records=evidence,
        safe_unlink=lambda *_args, **_kwargs: True,
        record_suppressed=lambda *args, **kwargs: suppressed.append((args, kwargs)),
    )

    assert result is False
    assert HostileValue.touched == 0
    assert evidence[0]["stage"] == "queue_reclaim_annotation_failed"
    assert evidence[0]["source_path"] == "<HostileValue unsupported_orphan_source_path>"
    assert evidence[0]["job_id"] == "missing_orphan_job_id"
    assert suppressed[0][1]["extra"]["source_path"] == "<HostileValue unsupported_reclaim_source_path>"
    quarantined = tmp_path / "quarantine" / "pending__pending.json"
    payload = json.loads(quarantined.read_text(encoding="utf-8"))
    assert payload["queue_failure"] is True
    assert payload["failure_info"]["source_path"] == "<HostileValue unsupported_reclaim_source_path>"


def test_stage1925_reclaim_publication_uses_canonical_quarantine_move(tmp_path: Path) -> None:
    HostileValue.touched = 0
    pending_path = tmp_path / "pending.json"
    pending_path.write_text("{}", encoding="utf-8")
    evidence = []

    result = _publish_reclaimed_pending_job(
        tmp_path,
        pending_path,
        {"file": "sample.bin", "queue_failure": True},
        source_path=tmp_path / "active" / "job.json",
        evidence_records=evidence,
        safe_unlink=lambda *_args, **_kwargs: True,
        record_suppressed=lambda *_args, **_kwargs: None,
    )

    assert result is False
    assert HostileValue.touched == 0
    assert [record["stage"] for record in evidence] == ["queue_reclaim_annotation_failed"]
    assert (tmp_path / "quarantine" / "pending__pending.json").is_file()


def test_stage1925_reclaim_publication_uses_only_canonical_writer(tmp_path: Path) -> None:
    HostileValue.touched = 0
    pending_path = tmp_path / "pending.json"
    pending_path.write_text("{}", encoding="utf-8")

    result = _publish_reclaimed_pending_job(
        tmp_path,
        pending_path,
        {
            "file": "sample.bin",
            "reclaimed_from_active": True,
            "queue_info": {"retry_pending_active": True},
        },
        source_path=tmp_path / "active" / "job.json",
        safe_unlink=lambda *_args, **_kwargs: True,
        record_suppressed=lambda *_args, **_kwargs: None,
    )

    assert result is True
    assert HostileValue.touched == 0


def test_stage1925_reclaim_publication_source_guard_closes_unsafe_routes() -> None:
    source = read_python_file(Path(__file__).resolve().parents[2] / "Virus_Scan/scheduler/queue/reclaim_publication.py")

    assert 'str(source_path or "")' not in source
    assert 'source_path or ""' not in source
    assert "dict(job or {})" not in source
    assert "quarantined = bool(" not in source
    assert "job.get(" not in source
    assert "safe_unlink(pending_path" not in source
    assert "return False" not in source
    assert "exact_bool(queue_write_json_replace" in source
    assert "write_json_replace:" not in source
    assert "atomic_replace:" not in source
    assert "scheduler_exception_text(exc)" in source
