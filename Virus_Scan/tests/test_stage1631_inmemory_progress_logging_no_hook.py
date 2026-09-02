from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.evidence.inmemory_progress_logging import maybe_log_inmemory_progress


class HostileScalar:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call bool")

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("do not call float")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("do not call int")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not call str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not call repr")


class HostileJobRecords:
    touched = 0

    def values(self):
        type(self).touched += 1
        raise RuntimeError("do not call values")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("do not len")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")


class CapturingLogger:
    def __init__(self):
        self.records = []

    def info(self, message, *args):
        # Force the same style of formatting a real logging backend would do.
        # All values must already be exact safe primitives.
        rendered = message % args
        self.records.append((rendered, args))


def test_stage1631_progress_logging_rejects_hostile_scalars_without_hooks():
    HostileScalar.touched = 0
    logger = CapturingLogger()
    rejections = []

    state = maybe_log_inmemory_progress(
        now=HostileScalar(),
        last_log_time=HostileScalar(),
        progress_every=HostileScalar(),
        completed=HostileScalar(),
        total_files=HostileScalar(),
        active_count=HostileScalar(),
        pending_count=HostileScalar(),
        live_workers=HostileScalar(),
        logical_inflight_count=0,
        queued_unstarted_count=0,
        logger=logger,
        last_progress_total=HostileScalar(),
        log_error=rejections.append,
    )

    assert HostileScalar.touched == 0
    assert logger.records == []
    assert state.last_progress_total == 0
    assert state.last_log_time == 0.0
    assert state.emitted is False
    joined = "\n".join(rejections)
    assert "unsafe_now" in joined
    assert "unsafe_last_log_time" in joined
    assert "unsafe_progress_every" in joined
    assert "unsafe_last_progress_total" in joined


def test_stage1631_progress_logging_rejects_hostile_owned_counter_scalars_without_hooks():
    HostileScalar.touched = 0
    logger = CapturingLogger()
    rejections = []

    state = maybe_log_inmemory_progress(
        now=100.0,
        last_log_time=0.0,
        progress_every=1,
        completed=3,
        total_files=5,
        active_count=2,
        pending_count=1,
        live_workers=4,
        logical_inflight_count=HostileScalar(),
        queued_unstarted_count=HostileScalar(),
        logger=logger,
        last_progress_total=0,
        log_error=rejections.append,
    )

    assert HostileScalar.touched == 0
    assert state.last_progress_total == 3
    assert state.last_log_time == 100.0
    assert state.emitted is True
    assert logger.records
    assert all(type(arg) is int for arg in logger.records[0][1])
    joined = "\n".join(rejections)
    assert "unsafe_logical_inflight_count" in joined
    assert "unsafe_queued_unstarted_count" in joined

def test_stage1631_progress_logging_preserves_valid_progress_message():
    logger = CapturingLogger()
    rejections = []
    job_records = {
        1: {"state": "running", "file": "a"},
        2: {"state": "queued", "file": "b"},
    }

    state = maybe_log_inmemory_progress(
        now=30.0,
        last_log_time=0.0,
        progress_every=10,
        completed=1,
        total_files=2,
        active_count=1,
        pending_count=1,
        live_workers=1,
        logical_inflight_count=1,
        queued_unstarted_count=1,
        logger=logger,
        last_progress_total=0,
        log_error=rejections.append,
    )

    assert state.last_progress_total == 1
    assert state.last_log_time == 30.0
    assert state.emitted is True
    assert rejections == []
    assert logger.records[0][1] == (1, 2, 1, 1, 1, 1, 1)


def test_stage1835_progress_logging_rejection_message_uses_exact_join_without_fstring():
    HostileScalar.touched = 0
    logger = CapturingLogger()
    rejections = []

    state = maybe_log_inmemory_progress(
        now=HostileScalar(),
        last_log_time=0.0,
        progress_every=1.0,
        completed=1,
        total_files=1,
        active_count=0,
        pending_count=0,
        live_workers=0,
        logical_inflight_count=0,
        queued_unstarted_count=0,
        logger=logger,
        last_progress_total=0,
        log_error=rejections.append,
    )

    assert state.emitted is False
    assert logger.records == []
    assert HostileScalar.touched == 0
    assert rejections == ["inmemory_progress_logging: now rejected without caller hooks: unsafe_now"]


def test_stage1835_progress_logging_source_has_no_dynamic_fstrings_or_fallback_routes():
    source = (
        Path(__file__).resolve().parents[1]
        / "scheduler"
        / "evidence"
        / "inmemory_progress_logging.py"
    ).read_text(encoding="utf-8")

    assert 'f"inmemory_progress_logging: {field} rejected without caller hooks: {reason}"' not in source
    assert 'f"unsafe_{field}"' not in source
    assert "fallback=" not in source
    assert "return None" not in source
    assert "pass" not in source
    assert 'return str.__add__("unsafe_", field)' in source
    assert 'str.__add__("inmemory_progress_logging: ", field)' in source
