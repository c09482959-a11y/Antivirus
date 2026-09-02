from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from Virus_Scan.scheduler.queue import claim_protection, claim_sidecar, claim_sidecar_policy, dirs, duplicate_guard, feed_marker
from Virus_Scan.scheduler.queue import claim_meta
from Virus_Scan.scheduler.queue.claim_meta import (
    read_claim_meta,
    remove_claim_meta,
    unreadable_claim_meta_info,
)


class HostileValue:
    hits: list[str] = []

    @classmethod
    def reset(cls) -> None:
        cls.hits = []

    def __str__(self):
        type(self).hits.append("str")
        raise AssertionError("__str__ must not execute")

    def __repr__(self):
        type(self).hits.append("repr")
        raise AssertionError("__repr__ must not execute")

    def __format__(self, _spec):
        type(self).hits.append("format")
        raise AssertionError("__format__ must not execute")

    def __bool__(self):
        type(self).hits.append("bool")
        raise AssertionError("__bool__ must not execute")

    def __iter__(self):
        type(self).hits.append("iter")
        raise AssertionError("__iter__ must not execute")

    def __float__(self):
        type(self).hits.append("float")
        raise AssertionError("__float__ must not execute")

    def __int__(self):
        type(self).hits.append("int")
        raise AssertionError("__int__ must not execute")

    def __fspath__(self):
        type(self).hits.append("fspath")
        raise AssertionError("__fspath__ must not execute")


class HostileUnlinkCallable:
    calls = 0

    def __call__(self, *_args, **_kwargs):  # pragma: no cover - must not execute
        type(self).calls += 1
        raise AssertionError("unlink callable object must not execute")


def test_stage1879_claim_meta_unreadable_uses_explicit_time_and_marker_evidence_without_hooks() -> None:
    HostileValue.reset()

    info = unreadable_claim_meta_info(
        RuntimeError("unreadable"),
        now=HostileValue(),
        marker=HostileValue(),
    )

    queue_info = info["queue_info"]
    assert queue_info["claim_meta_unreadable"] is True
    assert queue_info["heartbeat_time"]["unavailable_reason"] == "scheduler_claim_time_rejected"
    assert queue_info["progress_marker"] == "scheduler_claim_marker_rejected"
    assert queue_info["claim_meta_time_unavailable"] == "scheduler_claim_time_rejected"
    assert queue_info["claim_meta_marker_unavailable"] == "scheduler_claim_marker_rejected"
    assert HostileValue.hits == []


def test_stage1879_read_claim_meta_rejects_hostile_claim_path_before_callback_hooks() -> None:
    HostileValue.reset()
    reports = []

    result = read_claim_meta(
        HostileValue(),
        claim_meta_path=lambda _path: (_ for _ in ()).throw(AssertionError("callback must not run")),
        now=lambda: 10.0,
        report=lambda where, exc, **kwargs: reports.append((where, type(exc).__name__, kwargs)),
    )

    assert result["queue_info"]["claim_meta_unreadable"] is True
    assert reports == [("queue_claim_meta_path_failed", "ValueError", {"fatal": True})]
    assert HostileValue.hits == []


def test_stage1879_remove_claim_meta_rejects_hostile_claim_path_before_unlink_hooks() -> None:
    HostileValue.reset()
    reports = []

    removed = remove_claim_meta(
        HostileValue(),
        claim_meta_path=lambda _path: (_ for _ in ()).throw(AssertionError("path callback must not run")),
        safe_unlink=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unlink must not run")),
        report=lambda where, exc: reports.append((where, type(exc).__name__)),
    )

    assert removed is False
    assert reports == [("queue_claim_meta_cleanup_failed", "ValueError")]
    assert HostileValue.hits == []


def test_stage2023_remove_claim_meta_rejects_callable_object_unlink_dependency_without_calling_it(tmp_path) -> None:
    HostileUnlinkCallable.calls = 0
    reports = []

    removed = remove_claim_meta(
        tmp_path / "job.json",
        claim_meta_path=lambda _path: tmp_path / "job.json.claim",
        safe_unlink=HostileUnlinkCallable(),
        report=lambda where, exc: reports.append((where, type(exc).__name__, str(exc))),
    )

    assert removed is False
    assert reports == [
        (
            "queue_claim_meta_cleanup_failed",
            "ValueError",
            "scheduler_claim_meta_unlink_callable_rejected",
        )
    ]
    assert HostileUnlinkCallable.calls == 0


def test_stage1879_claim_meta_source_closes_fallback_and_fspath_routes() -> None:
    source = Path(claim_meta.__file__).read_text(encoding="utf-8")
    forbidden = (
        "fallback=0.0",
        "def _claim_marker(value, *, fallback)",
        "fallback=fallback",
        "return text or fallback",
        "os.fspath(mp)",
        "return False",
        "safe_unlink(",
    )
    for token in forbidden:
        assert token not in source


def test_stage1879_claim_protection_missing_liveness_rejects_hostile_pid_without_hooks() -> None:
    HostileValue.reset()
    reports = []

    with patch.object(
        claim_protection,
        "_process_queue_record_suppressed",
        lambda where, exc, **kwargs: reports.append((where, type(exc).__name__, kwargs)),
    ):
        assert claim_protection._queue_missing_worker_liveness(HostileValue()) is False

    assert reports[0][0] == "queue_active_claim_worker_liveness_dependency_missing"
    assert reports[0][2]["extra"]["worker_pid"] == "queue_worker_pid_rejected"
    assert reports[0][2]["extra"]["worker_pid_type"] == "HostileValue"
    assert HostileValue.hits == []


def test_stage1879_claim_sidecar_materializes_hostile_worker_context_without_hooks(tmp_path) -> None:
    HostileValue.reset()
    writes = []

    with patch.object(
        claim_sidecar,
        "queue_write_json_replace",
        lambda path, payload, **kwargs: writes.append((path, payload, kwargs)) or True,
    ):
        ok = claim_sidecar._queue_claim_sidecar_from_job(
            tmp_path / "active" / "job.json",
            {"file": "sample.bin", "queue_info": {"existing": True}},
            worker_id=HostileValue(),
            progress_marker=HostileValue(),
        )

    assert ok is True
    payload = writes[0][1]
    assert payload["worker_id"] == "queue_claim_worker_id_rejected"
    assert payload["progress_marker"] == "queue_claim_progress_marker_rejected"
    assert payload["claim_context_rejections"] == [
        "queue_claim_worker_id_rejected",
        "queue_claim_progress_marker_rejected",
    ]
    assert HostileValue.hits == []


def test_stage1879_claim_sidecar_rejects_hostile_paths_and_limits_without_hooks() -> None:
    HostileValue.reset()
    reports = []

    with patch.object(
        claim_sidecar,
        "_process_queue_record_suppressed",
        lambda where, exc, **kwargs: reports.append((where, type(exc).__name__, kwargs)),
    ):
        assert claim_sidecar._queue_cleanup_orphan_claim_meta(HostileValue()) == -1

    assert reports[0][0] == "queue_orphan_claim_active_dir_rejected"
    assert reports[0][2]["extra"]["active_dir_type"] == "HostileValue"
    assert HostileValue.hits == []


def test_stage1879_claim_sidecar_policy_rejects_hostile_text_and_write_path_without_hooks(tmp_path) -> None:
    HostileValue.reset()
    meta, queue_info = claim_sidecar_policy.build_claim_sidecar_meta(
        tmp_path / "active" / "job.json",
        {"file": "sample.bin"},
        now=100.0,
        pid=1234,
        worker_id=HostileValue(),
        progress_marker=HostileValue(),
    )

    assert meta["claim_job"] == "job.json"
    assert queue_info["worker_id"] == "queue_claim_worker_id_rejected"
    assert queue_info["progress_marker"] == "queue_claim_progress_marker_rejected"

    reports = []
    ok = claim_sidecar_policy.write_claim_sidecar_from_job(
        HostileValue(),
        {},
        now=lambda: 100.0,
        pid=lambda: 1234,
        write_claim_meta=lambda *_args, **_kwargs: True,
        report=lambda where, exc, **kwargs: reports.append((where, type(exc).__name__, kwargs)),
        os_fspath=lambda _path: (_ for _ in ()).throw(AssertionError("os_fspath must not run")),
    )

    assert ok is False
    assert reports[0][0] == "queue_claim_sidecar_write_failed"
    assert "HostileValue" in reports[0][2]["extra"]["claim"]
    assert HostileValue.hits == []


def test_stage2023_active_claim_grace_rejects_hostile_scalars_without_hooks() -> None:
    HostileValue.reset()
    reports = []

    grace = claim_sidecar_policy.active_claim_grace_sec(
        {"UMIGE_QUEUE_ACTIVE_CLAIM_GRACE_SEC": HostileValue()},
        default=HostileValue(),
        minimum=HostileValue(),
        report=lambda where, exc, **kwargs: reports.append((where, type(exc).__name__, kwargs)),
    )

    assert grace == 60.0
    assert reports == [("queue_active_claim_grace_invalid", "ValueError", {"fatal": False})]
    assert HostileValue.hits == []


def test_stage1879_claim_sidecar_sources_close_stale_routes() -> None:
    sidecar_source = Path(claim_sidecar.__file__).read_text(encoding="utf-8")
    protection_source = Path(claim_protection.__file__).read_text(encoding="utf-8")
    policy_source = Path(claim_sidecar_policy.__file__).read_text(encoding="utf-8")
    forbidden_by_source = {
        "claim_protection.py": (
            'extra={"worker_pid": str(worker_pid or "")}',
        ),
        "claim_sidecar.py": (
            'fallback="worker"',
            'fallback="claimed"',
            '"claim_path": os.fspath(p)',
            "return Path(os.fspath(safe_path) + \".claim\")",
            "fallback=0,",
            'fallback=""',
            '"claim_meta": os.fspath(claim)',
            '"base_claim": os.fspath(base)',
        ),
        "claim_sidecar_policy.py": (
            'str(worker_id or "worker")',
            'str(progress_marker or "claimed")',
            "hb = float(hb or 0)",
            "float(env.get(",
            "os.fspath(path)",
            "os_fspath(claim_path)",
        ),
    }
    sources = {
        "claim_protection.py": protection_source,
        "claim_sidecar.py": sidecar_source,
        "claim_sidecar_policy.py": policy_source,
    }
    for name, forbidden in forbidden_by_source.items():
        for token in forbidden:
            assert token not in sources[name]


def test_stage1879_queue_dirs_reject_hostile_cleanup_age_and_quarantine_context_without_hooks(tmp_path) -> None:
    HostileValue.reset()
    reports = []

    removed = dirs.cleanup_diagnostic_tmp_files(
        tmp_path,
        max_age_sec=HostileValue(),
        record_suppressed=lambda where, exc, **kwargs: reports.append((where, type(exc).__name__, kwargs)),
    )

    assert removed == -1
    assert reports[0][0] == "process_queue_diagnostic_tmp_max_age_rejected"
    assert reports[0][2]["extra"]["max_age_type"] == "HostileValue"

    reports.clear()
    with patch.object(
        dirs,
        "_process_queue_record_suppressed",
        lambda where, exc, **kwargs: reports.append((where, type(exc).__name__, kwargs)),
    ):
        quarantined = dirs.process_queue_quarantine_job(
            HostileValue(),
            reason=HostileValue(),
            job={"file": "sample.bin"},
        )

    assert quarantined is False
    assert reports[0][0] == "process_queue_quarantine_failed"
    assert HostileValue.hits == []


def test_stage1879_queue_dirs_invalid_claim_quarantine_reports_without_hooks() -> None:
    HostileValue.reset()
    reports = []

    with patch.object(
        dirs,
        "_process_queue_record_suppressed",
        lambda where, exc, **kwargs: reports.append((where, type(exc).__name__, kwargs)),
    ):
        assert dirs.process_queue_quarantine_invalid_claim(
            HostileValue(),
            reason=HostileValue(),
            job={"file": "sample.bin"},
        ) is False

    assert reports[0][0] == "process_queue_claim_quarantine_failed"
    assert "HostileValue" in reports[0][2]["extra"]["path"]
    assert reports[0][2]["extra"]["reason"] == "process_queue_claim_quarantine_reason_rejected"
    assert HostileValue.hits == []


def test_stage1879_queue_dirs_source_closes_stale_routes() -> None:
    source = Path(dirs.__file__).read_text(encoding="utf-8")
    forbidden = (
        "max_age = max(1.0, float(max_age_sec or 60.0))",
        "\n        return 0\n",
        'log_context=str(reason or "process_queue_claim_quarantine_resolution")',
        "os.makedirs(os.fspath(d), exist_ok=True)",
        'extra={"path": str(path), "reason": str(reason)}',
        'extra={"queue_dir": str(queue_dir)}',
    )
    for token in forbidden:
        assert token not in source


def test_stage1879_duplicate_guard_rejects_hostile_claim_path_without_hooks(tmp_path) -> None:
    HostileValue.reset()
    reports = []

    assert duplicate_guard.queue_duplicate_live_guard(
        tmp_path,
        HostileValue(),
        {"file": "sample.bin"},
        queue_job_dirs=lambda _queue_dir: (_ for _ in ()).throw(AssertionError("job dirs must not run")),
        safe_listdir=lambda _directory: (_ for _ in ()).throw(AssertionError("listdir must not run")),
        is_job_name=lambda _name: True,
        job_identity=lambda _job, _name: "file:sample.bin",
        read_json=lambda _path, default=None: default,
        report=lambda where, exc, **kwargs: reports.append((where, type(exc).__name__, kwargs)),
    ) is False

    assert reports[0][0] == "queue_duplicate_live_guard_failed_closed"
    assert "HostileValue" in reports[0][2]["extra"]["claim_path"]
    assert HostileValue.hits == []


def test_stage1879_duplicate_guard_source_closes_stale_routes() -> None:
    source = Path(duplicate_guard.__file__).read_text(encoding="utf-8")
    forbidden = (
        "safe_listdir(directory)",
        'extra={"claim_path": str(claim_path), "queue_dir": str(queue_dir)}',
        "\n        return False\n",
    )
    for token in forbidden:
        assert token not in source


def test_stage1879_feed_marker_rejects_hostile_queue_dir_without_hooks() -> None:
    HostileValue.reset()
    reports = []

    assert feed_marker.mark_process_queue_feed_complete(
        HostileValue(),
        record_suppressed=lambda where, exc, **kwargs: reports.append((where, type(exc).__name__, kwargs)),
    ) is False

    wheres = [where for where, _exc_name, _kwargs in reports]
    assert "queue_feed_complete_path_resolution_failed" in wheres
    assert "queue_feed_complete_persist_failed" in wheres
    assert HostileValue.hits == []


def test_stage1879_feed_marker_source_closes_stale_routes() -> None:
    source = Path(feed_marker.__file__).read_text(encoding="utf-8")
    forbidden = (
        'tmp = os.fspath(marker) + ".tmp"',
        'safe_unlink(tmp, log_context="queue_feed_complete_tmp_cleanup")',
        "\n        return False\n",
    )
    for token in forbidden:
        assert token not in source
