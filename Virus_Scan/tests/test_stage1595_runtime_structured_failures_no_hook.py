from __future__ import annotations

from Virus_Scan.runtime.structured_failures import (
    clear_failure_records,
    failure_snapshot,
    record_failure,
    record_suppressed_failure,
)


class HostileError(RuntimeError):
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify exception")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr exception")

    def __format__(self, _spec):
        type(self).touched += 1
        raise RuntimeError("do not format exception")


class HostileContext(dict):
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test context")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate context")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("do not call mapping items")

    def get(self, *_args, **_kwargs):
        type(self).touched += 1
        raise RuntimeError("do not call mapping get")


class HostileTelemetryProperty:
    touched = 0

    @property
    def event(self):
        type(self).touched += 1
        raise RuntimeError("do not inspect telemetry event property")


class HostileTag:
    touched = 0

    def __eq__(self, _other):
        type(self).touched += 1
        raise RuntimeError("do not compare hostile tag")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify hostile tag")


class HostileTags(list):
    touched = 0

    def __contains__(self, _item):
        type(self).touched += 1
        raise RuntimeError("do not call custom contains")


def test_stage1595_record_failure_rejects_hostile_exception_without_hooks():
    clear_failure_records()
    HostileError.touched = 0
    HostileContext.touched = 0
    HostileTelemetryProperty.touched = 0

    record = record_failure(
        "runtime",
        "hostile_failure_boundary",
        HostileError("boom"),
        telemetry=HostileTelemetryProperty(),
        context=HostileContext({"path": "owned"}),
    )

    assert HostileError.touched == 0
    assert HostileContext.touched == 0
    assert HostileTelemetryProperty.touched == 0
    assert record.error_type == "HostileError"
    assert record.message == "HostileError"
    assert record.trace_tail == "trace_unavailable:unsafe_exception_traceback_not_materialized_without_hooks"
    snapshot = failure_snapshot()["records"]
    assert snapshot[0]["message"] == "HostileError"
    assert snapshot[0]["provenance"]["queue_identity"] == ""


def test_stage1595_record_suppressed_failure_appends_exact_list_without_contains_or_tag_hooks():
    clear_failure_records()
    HostileError.touched = 0
    HostileTag.touched = 0
    HostileTags.touched = 0
    tags = [HostileTag(), "existing"]

    tag = record_suppressed_failure("unit.scan", HostileError("boom"), domain="scanner", tags=tags)

    assert HostileError.touched == 0
    assert HostileTag.touched == 0
    assert HostileTags.touched == 0
    assert tag == "failure_scanner_unit.scan"
    assert any(type(item) is str and item == "failure_scanner_unit.scan" for item in list.__iter__(tags))

from Virus_Scan.runtime.scanner_governance import ScannerContext, run_analyzer, scanner_failure_tags


class HostileScannerResult(dict):
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test analyzer result")

    def get(self, *_args, **_kwargs):
        type(self).touched += 1
        raise RuntimeError("do not call analyzer result get")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("do not call analyzer result items")


class HostileBaseTag:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify base tag")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr base tag")


def test_stage1595_scanner_failure_tags_ignore_hostile_base_tags_without_hooks():
    clear_failure_records()
    HostileBaseTag.touched = 0
    HostileError.touched = 0

    tags = scanner_failure_tags("unit.scan", HostileError("boom"), [HostileBaseTag(), "unity"])

    assert HostileBaseTag.touched == 0
    assert HostileError.touched == 0
    assert "unity" in tags
    assert "scanner_failure" in tags
    assert "scan_incomplete" in tags
    assert "failure_scanner_unit.scan" in tags


def test_stage1595_run_analyzer_rejects_mapping_subclass_without_get_bool_or_items():
    clear_failure_records()
    HostileScannerResult.touched = 0
    ctx = ScannerContext(path="x")

    result = run_analyzer(ctx, "unit.analyze", lambda: HostileScannerResult({"tags": ["unsafe"]}))

    assert HostileScannerResult.touched == 0
    assert result["degraded"] is True
    assert result["scanner_evidence_unavailable_reason"] == "non_materializable_analyzer_result"
    assert "scanner_failure" in result["tags"]
    assert "unsafe" not in ctx.tags
