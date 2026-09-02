"""Stage2636.11008 exact YARA single-scan execution instrumentation."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from types import SimpleNamespace
import zipfile

from Virus_Scan.contracts.yara_hits import YaraScanResult
from Virus_Scan.scheduler.execution.raw_stage_collector_dispatch import dispatch_raw_stage_collector
from Virus_Scan.scheduler.execution.scheduler_yara_result import obtain_scheduler_yara_result
from Virus_Scan.scheduler.workers.inmemory_worker_bootstrap_steps import (
    configure_worker_yara_metric_logging,
)
from Virus_Scan.yara.match import yara_scan, yara_scan_with_optional_zip


class CountingRules:
    def __init__(self) -> None:
        self.paths: list[str] = []

    def match(self, path: str) -> list[object]:
        self.paths.append(path)
        return []


def _complete_no_match() -> YaraScanResult:
    return YaraScanResult(
        status="complete_no_match",
        scan_pass_id="yscan_" + "1" * 64,
        physical_target_identity="content_sha256:" + "2" * 64,
        package_kind="unavailable",
        rule_source_digest="",
        compiled_cache_digest="",
        rule_catalog_digest="",
        hits=(),
        total_match_count=0,
        retained_match_count=0,
        duplicate_match_count=0,
        truncated_match_count=0,
        archive_member_count=0,
        scanned_member_count=0,
        failed_member_count=0,
    )


class SchedulerDeps:
    def __init__(self) -> None:
        self.calls = 0

    def yara_scan_with_optional_zip(self, _path: object, *, compiled_rules: object) -> YaraScanResult:
        assert compiled_rules == "selected-rules"
        self.calls += 1
        return _complete_no_match()


class RemovedGroupDeps:
    def __init__(self) -> None:
        self.scan_calls = 0

    def yara_scan(self, _path: object, *, compiled_rules: object) -> YaraScanResult:
        del compiled_rules
        self.scan_calls += 1
        return _complete_no_match()

    def raw_stage_failure_result(
        self, out: dict[str, object], collector: str, error: Exception, *, stage: str,
    ) -> dict[str, object]:
        out["failure"] = {"collector": collector, "reason": str(error), "stage": stage}
        return out


def test_phase3_ordinary_file_invokes_engine_once(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    rules = CountingRules()
    result = yara_scan(sample, compiled_rules=rules)
    assert result.status == "complete_no_match"
    assert rules.paths == [sample.as_posix()]


def test_phase3_canonical_scan_emits_one_structured_metric_per_engine_call(
    tmp_path: Path, caplog: object,
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    rules = CountingRules()
    caplog.set_level(logging.INFO, logger="Virus_Scan.yara.match")
    result = yara_scan(sample, compiled_rules=rules)
    records = []
    for record in caplog.records:
        message = record.getMessage()
        marker_text = "[YARA_SCAN_METRIC] "
        if marker_text in message:
            records.append(json.loads(message.split(marker_text, 1)[1]))
    assert len(records) == 1
    assert records[0]["engine_match_invoked"] is True
    assert records[0]["scan_pass_id"] == result.scan_pass_id
    assert records[0]["status"] == "complete_no_match"
    assert type(records[0]["elapsed_ns"]) is int
    assert records[0]["elapsed_ns"] >= 0
    assert rules.paths == [sample.as_posix()]


def test_phase3_worker_metric_handler_is_opt_in_and_idempotent(
    capsys: object,
) -> None:
    logger = logging.getLogger("Virus_Scan.yara.match")
    handler_name = "umige_yara_scan_metric_stderr"
    original_level = logger.level
    original_propagate = logger.propagate
    suppressed: list[tuple[str, str]] = []

    def record_suppressed(context: str, exc: BaseException) -> None:
        suppressed.append((context, type(exc).__name__))

    try:
        for handler in tuple(logger.handlers):
            if handler.get_name() == handler_name:
                logger.removeHandler(handler)
        for _index in range(2):
            configure_worker_yara_metric_logging(
                enabled=True,
                record_bootstrap_suppressed=record_suppressed,
                recoverable_exceptions=(
                    OSError, ValueError, RuntimeError, TypeError, AttributeError,
                ),
            )
        matching = tuple(
            handler for handler in logger.handlers
            if handler.get_name() == handler_name
        )
        assert len(matching) == 1
        logger.info('[YARA_SCAN_METRIC] {"scan_pass_id":"yscan_test"}')
        assert capsys.readouterr().err.count("[YARA_SCAN_METRIC]") == 1
        assert suppressed == []
    finally:
        for handler in tuple(logger.handlers):
            if handler.get_name() == handler_name:
                logger.removeHandler(handler)
        logger.setLevel(original_level)
        logger.propagate = original_propagate


def test_phase3_archive_invokes_engine_once_per_physical_member(tmp_path: Path) -> None:
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("a.bin", b"a")
        handle.writestr("b.bin", b"b")
        handle.writestr("nested/c.bin", b"c")
    rules = CountingRules()
    result = yara_scan_with_optional_zip(archive, compiled_rules=rules)
    assert result.status == "complete_no_match"
    assert result.archive_member_count == 3
    assert len(rules.paths) == 3
    assert len(set(rules.paths)) == 3


def test_phase3_direct_scheduler_invokes_canonical_scan_once() -> None:
    deps = SchedulerDeps()
    request = SimpleNamespace(yara_enabled=True, compiled_rules="selected-rules")
    result = obtain_scheduler_yara_result(
        path="sample.bin",
        yara_enabled=request.yara_enabled,
        compiled_rules=request.compiled_rules,
        yara_scan_with_optional_zip=deps.yara_scan_with_optional_zip,
    )
    assert result.status == "complete_no_match"
    assert deps.calls == 1


def test_phase3_invalid_raw_evidence_does_not_suppress_required_scan() -> None:
    deps = SchedulerDeps()
    request = SimpleNamespace(yara_enabled=True, compiled_rules="selected-rules")
    result = obtain_scheduler_yara_result(
        path="sample.bin",
        yara_enabled=request.yara_enabled,
        compiled_rules=request.compiled_rules,
        yara_scan_with_optional_zip=deps.yara_scan_with_optional_zip,
        existing_result=(),
    )
    assert result.status == "complete_no_match"
    assert deps.calls == 1


def test_phase3_removed_multi_group_collector_cannot_rescan_target() -> None:
    deps = RemovedGroupDeps()
    out = dispatch_raw_stage_collector(
        job={"collector": "yara_group", "group_index": 0, "group_count": 2},
        path="same-target.bin",
        collector="yara_group",
        start=0,
        size=0,
        out={},
        deps=deps,
    )
    assert out["failure"]["stage"] == "raw_stage_unknown_collector"
    assert deps.scan_calls == 0
