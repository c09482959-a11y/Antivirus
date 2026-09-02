"""Stage2145: raw queue progress defaults become replayable evidence."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.queue.raw_queue_progress import file_has_recent_raw_owner_progress
from Virus_Scan.tests.support.static_inventory import read_python_file


class _HostileScalar:
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


class _MalformedStore:
    def __init__(self, queue_dir: Path, file_id: str) -> None:
        self.path = queue_dir / (file_id + ".json")

    def load(self) -> object:
        return _HostileScalar()

    @staticmethod
    def is_complete(_data: object) -> bool:
        raise AssertionError("malformed mapping must stop before completion check")


class _HostileBoolStore:
    def __init__(self, queue_dir: Path, file_id: str) -> None:
        self.path = queue_dir / (file_id + ".json")

    def load(self) -> dict[str, object]:
        return {"file_id": "fid", "expected": 2, "completed": 1, "updated_at": 100.0}

    @staticmethod
    def is_complete(_data: object) -> object:
        return _HostileScalar()


def test_stage2145_malformed_raw_progress_mapping_is_unavailable_evidence(tmp_path: Path) -> None:
    _HostileScalar.touched = 0
    reports: list[tuple[str, object, bool, dict[str, object]]] = []

    info = file_has_recent_raw_owner_progress(
        tmp_path,
        tmp_path / "sample.bin",
        global_raw_file_id=lambda _path: "fid",
        accumulator_store_cls=_MalformedStore,
        queue_now=lambda: 110.0,
        raw_stage_progress_recent=lambda *_args, **_kwargs: False,
        report=lambda stage, exc=None, *, fatal=False, extra=None: reports.append((stage, exc, fatal, extra or {})),
    )

    assert info["recent"] is False
    assert info["progress_mapping_unavailable"] == {
        "raw_progress_mapping_available": False,
        "raw_progress_mapping_reason": "raw_progress_mapping_rejected",
    }
    assert reports[0][0] == "queue_raw_owner_progress_mapping_unavailable"
    assert reports[0][2] is False
    assert reports[0][3]["raw_progress_mapping_available"] is False
    assert reports[0][3]["queue_dir"] == str(tmp_path)
    assert _HostileScalar.touched == 0


def test_stage2145_raw_progress_bool_rejections_are_replayable_without_hooks(tmp_path: Path) -> None:
    _HostileScalar.touched = 0
    reports: list[tuple[str, object, bool, dict[str, object]]] = []

    info = file_has_recent_raw_owner_progress(
        tmp_path,
        tmp_path / "sample.bin",
        quiet_sec=30,
        global_raw_file_id=lambda _path: "fid",
        accumulator_store_cls=_HostileBoolStore,
        queue_now=lambda: 110.0,
        raw_stage_progress_recent=lambda *_args, **_kwargs: _HostileScalar(),
        report=lambda stage, exc=None, *, fatal=False, extra=None: reports.append((stage, exc, fatal, extra or {})),
    )

    assert info["has_accumulator"] is True
    assert info["complete"] is False
    assert info["recent"] is True
    assert info["complete_unavailable"]["raw_progress_bool_reason"] == "raw_progress_complete_rejected"
    assert info["recent_global_unavailable"]["raw_progress_bool_reason"] == "raw_progress_recent_global_rejected"
    report_names = [stage for stage, *_rest in reports]
    assert "queue_raw_owner_progress_complete_unavailable" in report_names
    assert "queue_raw_owner_progress_recent_global_unavailable" in report_names
    assert _HostileScalar.touched == 0


def test_stage2145_raw_queue_progress_source_removes_hidden_default_routes() -> None:
    source = read_python_file(Path("Virus_Scan/scheduler/queue/raw_queue_progress.py"))

    assert "def _mapping(value: Any) -> dict[str, Any] | None:" not in source
    assert "def _safe_bool(value: Any) -> bool:" not in source
    assert "return False\n\n\ndef _quiet_seconds" not in source
    assert "return 0.0\n\n\ndef file_has_recent_raw_owner_progress" not in source
    assert "queue_raw_owner_progress_mapping_unavailable" in source
    assert "queue_raw_owner_progress_complete_unavailable" in source
    assert "queue_raw_owner_progress_recent_global_unavailable" in source
