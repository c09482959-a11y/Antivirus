from Virus_Scan.scheduler.evidence.inmemory_ewma import update_ewma
from Virus_Scan.scheduler.evidence.raw_collector_context import raw_collector_context_failure


class HostileText:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")


class HostilePath:
    touched = 0

    def __fspath__(self):
        type(self).touched += 1
        raise RuntimeError("do not fspath")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify path")


class HostileStart:
    touched = 0

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("do not int")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")


class HostileTags:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")


class HostileFloat:
    touched = 0

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("do not float")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify")


def test_raw_collector_context_failure_rejects_hostile_inputs_without_hooks():
    for cls in (HostileText, HostilePath, HostileStart, HostileTags):
        cls.touched = 0
    calls = []
    degraded_inputs = []

    out = raw_collector_context_failure(
        HostileTags(),
        HostileText(),
        RuntimeError("ctx failed"),
        path=HostilePath(),
        start=HostileStart(),
        report=lambda stage, exc, **kw: calls.append((stage, type(exc).__name__, kw)),
        scanner_degraded_tags=lambda tags: degraded_inputs.append(tuple(tags)) or list(tags) + ["scanner_failure"],
    )

    assert HostileText.touched == 0
    assert HostilePath.touched == 0
    assert HostileStart.touched == 0
    assert HostileTags.touched == 0
    assert out == ["raw_context_scan_failed", "scanner_failure"]
    assert degraded_inputs == [("raw_context_scan_failed",)]
    assert calls[0][0] == "raw_raw_collector_context_scan_failed"
    extra = calls[0][2]["extra"]
    assert extra["collector"] == "raw_collector"
    assert extra["collector_evidence"]["unsupported_scheduler_value"] is True
    assert extra["path_evidence"]["unsupported_scheduler_value"] is True
    assert extra["start_evidence"]["unsupported_scheduler_value"] is True
    assert extra["tags_evidence"]["unsupported_scheduler_value"] is True


def test_raw_collector_context_failure_preserves_exact_primitive_provenance():
    calls = []
    out = raw_collector_context_failure(
        ["existing"],
        "bytecode_chunk",
        RuntimeError("ctx failed"),
        path="sample.py",
        start=12,
        report=lambda stage, exc, **kw: calls.append((stage, type(exc).__name__, kw)),
        scanner_degraded_tags=lambda tags: list(tags) + ["scanner_failure"],
    )

    assert out == ["existing", "raw_context_scan_failed", "scanner_failure"]
    assert calls[0][0] == "raw_bytecode_chunk_context_scan_failed"
    assert calls[0][2]["extra"] == {"path": "sample.py", "start": 12, "collector": "bytecode_chunk"}


def test_update_ewma_rejects_hostile_numeric_and_key_without_hooks():
    HostileText.touched = 0
    HostileFloat.touched = 0
    state = {}

    bad_key = update_ewma(HostileText(), 1.0, state=state)
    bad_value = update_ewma("dispatch_backpressure", HostileFloat(), state=state)
    bad_alpha = update_ewma("dispatch_backpressure", 1.0, state=state, alpha=HostileFloat())

    assert HostileText.touched == 0
    assert HostileFloat.touched == 0
    assert state == {}
    assert bad_key["unsupported_scheduler_value"] is True
    assert bad_key["field_name"] == "ewma_name"
    assert bad_value["unsupported_scheduler_value"] is True
    assert bad_value["field_name"] == "ewma_value"
    assert bad_alpha["unsupported_scheduler_value"] is True
    assert bad_alpha["field_name"] == "ewma_alpha"


def test_update_ewma_preserves_exact_numeric_behavior():
    state = {}
    assert update_ewma("dispatch_backpressure", 1.0, state=state, alpha=0.5) == 1.0
    assert update_ewma("dispatch_backpressure", 0.0, state=state, alpha=0.5) == 0.5
    assert state == {"dispatch_backpressure": 0.5}
