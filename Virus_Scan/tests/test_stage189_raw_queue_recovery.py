from Virus_Scan.scheduler.queue.raw_queue_recovery import raw_stage_progress_recent


def test_raw_stage_progress_recent_tracks_accounting_movement():
    now = [100.0]
    counts = [{"raw_pending": 1, "raw_active": 0, "raw_done": 0, "raw_failed": 0}]
    state = {}
    errors = []

    def progress_counts(_queue_dir):
        return counts[-1]

    assert raw_stage_progress_recent(
        "q", progress_counts=progress_counts, queue_now=lambda: now[0], state=state, report=lambda s, e: errors.append(s)
    ) is True
    now[0] += 10
    assert raw_stage_progress_recent(
        "q", quiet_sec=15, progress_counts=progress_counts, queue_now=lambda: now[0], state=state, report=lambda s, e: errors.append(s)
    ) is True
    now[0] += 20
    assert raw_stage_progress_recent(
        "q", quiet_sec=15, progress_counts=progress_counts, queue_now=lambda: now[0], state=state, report=lambda s, e: errors.append(s)
    ) is False
    counts.append({"raw_pending": 0, "raw_active": 2, "raw_done": 0, "raw_failed": 0})
    now[0] += 1
    assert raw_stage_progress_recent(
        "q", quiet_sec=15, progress_counts=progress_counts, queue_now=lambda: now[0], state=state, report=lambda s, e: errors.append(s)
    ) is True
    assert errors == []


def test_raw_stage_progress_recent_reports_bad_quiet_and_count_failure():
    errors = []
    assert raw_stage_progress_recent(
        "q",
        quiet_sec="bad",
        progress_counts=lambda _q: (_ for _ in ()).throw(RuntimeError("boom")),
        queue_now=lambda: 1.0,
        state={},
        report=lambda s, e: errors.append(s),
    ) is True
    assert "raw_stage_progress_quiet_invalid" in errors
    assert "raw_stage_progress_count_failed" in errors
