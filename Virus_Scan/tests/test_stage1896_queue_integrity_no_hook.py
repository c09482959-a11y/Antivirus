from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file, read_python_file


import ast
from pathlib import Path

import pytest

from Virus_Scan.scheduler.queue.integrity import (
    QUEUE_IDENTITY_COLLECTION_FAILED,
    QueueIntegrityVerificationRequest,
    collect_jobs_by_identity,
    verify_and_repair_queue_integrity,
)
from Virus_Scan.scheduler.queue.integrity_contracts import QueueIntegritySummary
import Virus_Scan.scheduler.queue.orphan_recovery as orphan_recovery

_SOURCE_FILES = (
    Path("Virus_Scan/scheduler/queue/integrity.py"),
    Path("Virus_Scan/scheduler/queue/integrity_contracts.py"),
    Path("Virus_Scan/scheduler/queue/orphan_recovery.py"),
)


class HostileBoundaryObject:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    @classmethod
    def _touch(cls, where: str) -> None:
        cls.touched += 1
        raise RuntimeError(where + " hook must not execute")

    def __getattribute__(self, name):  # pragma: no cover - failure path only
        if name in {"reset", "_touch", "touched", "__class__"}:
            return object.__getattribute__(self, name)
        type(self)._touch("attribute")

    def __bool__(self):  # pragma: no cover - failure path only
        type(self)._touch("bool")

    def __str__(self):  # pragma: no cover - failure path only
        type(self)._touch("str")

    def __repr__(self):  # pragma: no cover - failure path only
        type(self)._touch("repr")

    def __format__(self, _spec):  # pragma: no cover - failure path only
        type(self)._touch("format")

    def __iter__(self):  # pragma: no cover - failure path only
        type(self)._touch("iter")

    def __fspath__(self):  # pragma: no cover - failure path only
        type(self)._touch("fspath")

    def __truediv__(self, _other):  # pragma: no cover - failure path only
        type(self)._touch("path_join")

    def items(self):  # pragma: no cover - failure path only
        type(self)._touch("items")

    def get(self, _key, _default=None):  # pragma: no cover - failure path only
        type(self)._touch("get")


@pytest.mark.parametrize("directory_index", range(4))
def test_stage1896_collect_jobs_rejects_hostile_job_directories_without_hooks(directory_index: int) -> None:
    HostileBoundaryObject.reset()
    reports = []
    directories = ["pending", "active", "done", "failed"]
    directories[directory_index] = HostileBoundaryObject()

    result = collect_jobs_by_identity(
        "queue-root",
        job_dirs=lambda _queue_dir: tuple(directories),
        safe_listdir=lambda _directory: [],
        is_job_json_name=lambda _name: False,
        read_json=lambda *_args, **_kwargs: {},
        job_identity=lambda *_args, **_kwargs: "unused",
        merge_claim_meta=lambda _path, job: job,
        report=lambda stage, exc, **kw: reports.append((stage, type(exc).__name__, kw)),
    )

    assert HostileBoundaryObject.touched == 0
    assert QUEUE_IDENTITY_COLLECTION_FAILED in result
    record = result[QUEUE_IDENTITY_COLLECTION_FAILED][0]
    assert record["queue_identity_collection_failed"] is True
    assert record["queue_integrity_unavailable"] is True
    assert reports[0][0] == "queue_identity_collection_failed"
    assert reports[0][1] == "TypeError"
    assert reports[0][2]["fatal"] is True


def test_stage1896_verify_rejects_hostile_identity_groups_without_mapping_hooks(tmp_path: Path) -> None:
    HostileBoundaryObject.reset()
    reports = []

    summary = verify_and_repair_queue_integrity(QueueIntegrityVerificationRequest(
        tmp_path,
        all_files=None,
        phase="startup",
        repair=True,
        ensure_dirs=lambda _q: None,
        cleanup_diagnostic_tmp_files=lambda _q, max_age_sec=60.0: None,
        identity_collector=lambda _q: HostileBoundaryObject(),
        active_claim_is_protected=lambda *a, **k: False,
        quarantine_job=lambda *a, **k: True,
        queue_now=lambda: 1.0,
        report=lambda stage, exc, **kw: reports.append((stage, type(exc).__name__, kw)),
    ))

    assert HostileBoundaryObject.touched == 0
    assert summary["integrity_complete"] is False
    assert "queue identity groups mapping rejected" in summary["integrity_error"]
    assert reports[0][0] == "queue_integrity_verify_repair_failed"
    assert reports[0][1] == "TypeError"
    assert reports[0][2]["fatal"] is True


def test_stage1896_duplicate_records_are_normalized_before_rank_and_quarantine(tmp_path: Path) -> None:
    protected_path = tmp_path / "active.json"
    duplicate_path = tmp_path / "pending.json"
    seen = []
    groups = {
        "file:x": (
            {"state": "active", "path": protected_path, "name": "active.json", "job": {"file": "x"}},
            {"state": "pending", "path": duplicate_path, "name": "pending.json", "job": {"file": "x"}},
        )
    }

    summary = verify_and_repair_queue_integrity(QueueIntegrityVerificationRequest(
        tmp_path,
        all_files=None,
        phase="startup",
        repair=True,
        ensure_dirs=lambda _q: None,
        cleanup_diagnostic_tmp_files=lambda _q, max_age_sec=60.0: None,
        identity_collector=lambda _q: groups,
        active_claim_is_protected=lambda path, **_kw: path == protected_path,
        quarantine_job=lambda path, **kw: seen.append((path, kw)) or True,
        queue_now=lambda: 1.0,
        report=lambda *a, **k: None,
    ))

    assert summary["integrity_complete"] is True
    assert summary["duplicates"] == 1
    assert summary["quarantined"] == 1
    assert seen == [(duplicate_path, {"reason": "duplicate_queue_identity_keep_active", "job": {"file": "x"}, "identity": "file:x"})]


def test_stage1896_queue_integrity_forensic_context_rejects_hostile_text_without_hooks() -> None:
    HostileBoundaryObject.reset()
    summary = QueueIntegritySummary(integrity_complete=False, integrity_error="scan_incomplete")

    with pytest.raises(RuntimeError, match="queue_integrity: queue integrity did not complete: scan_incomplete"):
        summary.assert_forensic_complete(context=HostileBoundaryObject())

    assert HostileBoundaryObject.touched == 0


def test_stage1896_queue_integrity_source_has_no_reintroduced_hook_routes() -> None:
    forbidden_text = (
        "groups.items(",
        "safe_listdir(d)",
        "context=f\"",
        "queue_integrity_{",
        "it.get(",
        "keep.get(",
        "raise RuntimeError(f",
        "logging.warning(f",
        "getattr(policy",
        "str(src)",
        "str(queue_dir)",
        "_process_queue_log_error(f",
        "logging.info(f",
    )
    for source in _SOURCE_FILES:
        text = read_python_file(source)
        tree = parse_python_file(source)
        assert not [node.lineno for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)]
        for forbidden in forbidden_text:
            assert forbidden not in text



def test_stage1896_orphan_recovery_rejects_hostile_policy_without_getattr() -> None:
    HostileBoundaryObject.reset()

    with pytest.raises(TypeError, match="queue reclaim policy rejected"):
        orphan_recovery._queue_reclaim_policy_fields(HostileBoundaryObject())

    assert HostileBoundaryObject.touched == 0
