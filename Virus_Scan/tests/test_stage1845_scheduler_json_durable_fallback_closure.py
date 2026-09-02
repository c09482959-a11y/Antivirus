"""Stage 1845: durable scheduler JSON fallback/sentinel closure."""
from __future__ import annotations

from dataclasses import fields
from pathlib import Path

from Virus_Scan.scheduler.evidence.scheduler_json_writer import raw_unlink_quiet, write_process_queue_json_durable
from Virus_Scan.scheduler.queue import raw_accumulator_store as raw_store


class HostileContext:
    touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("context __str__ must not be invoked")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("context __format__ must not be invoked")


def test_stage1845_raw_unlink_quiet_uses_canonical_unlink_not_dependency_hook(tmp_path: Path) -> None:
    target = tmp_path / "cleanup.json"
    target.write_text("{}", encoding="utf-8")

    deps = raw_store.raw_json_dependencies()
    assert "safe_unlink" not in {field.name for field in fields(deps)}

    assert raw_unlink_quiet(target, log_context="stage1845_cleanup", deps=deps) is True

    assert not target.exists()


def test_stage1845_process_queue_context_rejection_is_no_hook_and_explicit(tmp_path: Path) -> None:
    HostileContext.touched = 0
    assert write_process_queue_json_durable(
        tmp_path / "record.tmp",
        tmp_path / "record.json",
        {"schema_version": 1, "ok": True},
        log_context=HostileContext(),
    ) is False
    assert HostileContext.touched == 0
    assert not (tmp_path / "record.json").exists()


def test_stage1845_scheduler_json_durable_sources_close_fallback_sentinel_routes() -> None:
    root = Path(__file__).resolve().parents[1]
    durable_source = (root / "scheduler/evidence/scheduler_json_durable.py").read_text(encoding="utf-8")
    support_source = (root / "scheduler/evidence/scheduler_json_durable_support.py").read_text(encoding="utf-8")
    combined_source = "\n".join((durable_source, support_source))

    for forbidden in (
        "_record_raw_fallback",
        "fallback=",
        "return False",
        "os.fspath",
        "f\"{safe_context}",
        "deps.safe_unlink(",
        "record_suppressed(f\"",
    ):
        assert forbidden not in combined_source

    assert "default_text=" in durable_source
    assert "RAW_JSON_OPERATION_FAILED" in durable_source
