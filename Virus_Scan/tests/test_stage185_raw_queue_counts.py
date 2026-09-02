from Virus_Scan.scheduler.queue.raw_queue_counts import pending_file_jobs, raw_queue_live_count


def test_pending_file_jobs_counts_only_non_raw_pending_jobs(tmp_path):
    q = tmp_path
    pending = q / "pending"
    pending.mkdir()
    (pending / "file.json").write_text("{}", encoding="utf-8")
    (pending / "raw.json").write_text("{}", encoding="utf-8")
    reports = []
    jobs = {"file.json": {"job_type": "file"}, "raw.json": {"job_type": "raw_stage"}}

    assert pending_file_jobs(
        q,
        queue_job_dirs=lambda qd: (pending, qd / "active", qd / "done", qd / "failed"),
        safe_listdir=lambda d: [p.name for p in d.iterdir()],
        read_json_file=lambda path, default=None: jobs[path.name],
        report=lambda *a, **kw: reports.append((a, kw)),
    ) == 1
    assert reports == []


def test_pending_file_jobs_returns_unknown_sentinel_on_read_failure(tmp_path):
    reports = []
    assert pending_file_jobs(
        tmp_path,
        queue_job_dirs=lambda qd: (_ for _ in ()).throw(OSError("blocked")),
        safe_listdir=lambda d: [],
        read_json_file=lambda path, default=None: {},
        report=lambda *a, **kw: reports.append((a, kw)),
    ) == -1
    assert reports and reports[0][0][0] == "raw_pending_file_jobs_unknown"


def test_raw_queue_live_count_fails_closed_to_cap():
    reports = []
    assert raw_queue_live_count(
        "queue",
        queue_progress_counts=lambda q: (_ for _ in ()).throw(OSError("unreadable")),
        report=lambda ctx, exc: reports.append((ctx, type(exc).__name__)),
        live_hard_cap=77,
    ) == 77
    assert reports == [("raw_live_count_failed_closed", "OSError")]
