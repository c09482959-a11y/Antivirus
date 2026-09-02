from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.scheduler.queue.raw_queue_quarantine import (
    cleanup_orphan_claim_sidecars,
    quarantine_dir,
    quarantine_job_decision,
    quarantine_sidecar_payload,
    remove_claim_sidecar_for_terminal_move,
)


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

    def __int__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile int hook touched")

    def __float__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile float hook touched")

    def __fspath__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile fspath hook touched")


class HostileMapping:
    touched = 0

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile iter hook touched")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile mapping bool touched")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile mapping str touched")


def test_stage1922_quarantine_dir_rejects_hostile_queue_dir_without_fspath_or_bool_hooks() -> None:
    HostileValue.touched = 0
    reports = []
    result = quarantine_dir(HostileValue(), report=lambda *args, **kwargs: reports.append((args, kwargs)))

    assert result == Path("quarantine")
    assert reports
    assert reports[0][1]["extra"]["queue_dir_reason"] == "scheduler_path_rejected"
    assert HostileValue.touched == 0


def test_stage1922_sidecar_payload_rejects_hostile_identity_reason_and_state_without_hooks(tmp_path: Path) -> None:
    HostileValue.touched = 0
    payload = quarantine_sidecar_payload(
        reason=HostileValue(),
        identity=HostileValue(),
        source_state=HostileValue(),
        destination=tmp_path / "quarantine" / "active__job.json",
        now=HostileValue(),
    )

    assert payload["quarantine_reason"] == "queue_quarantine_reason_unavailable"
    assert payload["queue_identity"].startswith("identity_unavailable:")
    assert payload["quarantine_source_state"] == "queue_quarantine_source_state_unavailable"
    assert payload["quarantine_time"] == 0.0
    assert payload["quarantine_job"] == "active__job.json"
    assert HostileValue.touched == 0


def test_stage1922_sidecar_cleanup_rejects_hostile_marker_path_and_result_without_hooks(tmp_path: Path) -> None:
    HostileValue.touched = 0
    reports = []
    removed = remove_claim_sidecar_for_terminal_move(
        tmp_path / "active" / "job.json",
        remove_claim_meta=lambda _path: HostileValue(),
        report=lambda *args, **kwargs: reports.append((args, kwargs)),
        marker=HostileValue(),
    )

    assert removed is False
    assert reports == []
    assert HostileValue.touched == 0


def test_stage1922_orphan_cleanup_rejects_hostile_marker_max_and_result_without_hooks(tmp_path: Path) -> None:
    HostileValue.touched = 0
    removed = cleanup_orphan_claim_sidecars(
        tmp_path / "active",
        cleanup_orphans=lambda *_args, **_kwargs: HostileValue(),
        max_remove=HostileValue(),
        report=lambda *_args, **_kwargs: None,
        marker=HostileValue(),
        claim_path=tmp_path / "active" / "job.json",
    )

    assert removed == 0
    assert HostileValue.touched == 0


def test_stage1922_quarantine_job_rejects_hostile_path_and_payload_without_hooks(tmp_path: Path) -> None:
    HostileValue.touched = 0
    HostileMapping.touched = 0
    issues = []
    logs = []

    result = quarantine_job_decision(
        HostileValue(),
        job=HostileMapping(),
        identity=HostileValue(),
        active_claim_is_protected=lambda *_args, **_kwargs: HostileValue(),
        quarantine_dir=lambda _queue_dir: tmp_path / "quarantine",
        read_json_file=lambda _path: HostileMapping(),
        job_identity=lambda *_args: HostileValue(),
        quarantine_destination=lambda path, *, quarantine_root: (Path(quarantine_root) / Path(path).name, "active"),
        remove_claim_sidecar_for_terminal_move=lambda *_args, **_kwargs: HostileValue(),
        remove_claim_meta=lambda _path: HostileValue(),
        cleanup_orphan_claim_sidecars=lambda *_args, **_kwargs: HostileValue(),
        cleanup_orphans=lambda *_args, **_kwargs: HostileValue(),
        orphan_cleanup_max=HostileValue(),
        write_quarantine_sidecar=lambda *_args, **_kwargs: None,
        quarantine_sidecar_payload=lambda **_kwargs: {},
        report=lambda *_args, **_kwargs: None,
        report_issue=lambda *args, **_kwargs: issues.append(args),
        log_error=lambda message: logs.append(message),
    ).quarantined

    assert result is False
    assert issues and issues[-1][0] == "queue_quarantine_failed"
    assert logs and "queue_quarantine_path_unavailable" in logs[0]
    assert HostileValue.touched == 0
    assert HostileMapping.touched == 0


def test_stage1922_raw_queue_quarantine_source_guard_closes_unsafe_routes() -> None:
    source = read_python_file(Path(__file__).resolve().parents[2] / "Virus_Scan/scheduler/queue/raw_queue_quarantine.py")

    assert "os.fspath" not in source
    assert "str(marker)" not in source
    assert "return False\n    except" not in source
    assert "return 0\n    except" not in source
    assert "identity_unavailable:{type(identity).__module__}.{type(identity).__qualname__}" not in source
    assert "raise ValueError(f\"queue quarantine payload must be a mapping" not in source
    assert "log_error(f\"queue quarantine failed" not in source
