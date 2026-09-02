import json
from pathlib import Path

import pytest

from Virus_Scan.scheduler.api.contracts import QueueResultMergeError
from Virus_Scan.scheduler.queue.result_merge import load_queue_file_results, done_jobs_missing_results


def test_load_queue_file_results_fails_closed_on_bad_record(tmp_path):
    results_dir = tmp_path / 'file_results'
    results_dir.mkdir()
    (results_dir / 'bad.result.json').write_text('{"file":"a"}', encoding='utf-8')
    seen = []

    def read_json(path, default=None):
            return json.loads(Path(path).read_text(encoding='utf-8'))

    with pytest.raises(QueueResultMergeError):
        load_queue_file_results(
            tmp_path,
            file_results_dir=lambda q: results_dir,
            safe_listdir=lambda d: [p.name for p in Path(d).iterdir()],
            read_json=read_json,
            report=lambda *a, **kw: seen.append((a, kw)),
        )
    assert seen and seen[0][0][0] == 'queue_file_result_readback_failed'


def test_done_jobs_missing_results_reports_unmerged_file_jobs(tmp_path):
    pending = tmp_path / 'pending'; active = tmp_path / 'active'; done = tmp_path / 'done'; failed = tmp_path / 'failed'
    for d in (pending, active, done, failed):
        d.mkdir()
    (done / 'job1.json').write_text('{"file":"missing.bin"}', encoding='utf-8')
    (done / 'raw_job.json').write_text('{"type":"raw", "file":"chunk.bin"}', encoding='utf-8')

    def read_json(path, default=None):
        return json.loads(Path(path).read_text(encoding='utf-8'))

    missing = done_jobs_missing_results(
        tmp_path,
        {},
        job_dirs=lambda q: (pending, active, done, failed),
        safe_listdir=lambda d: [p.name for p in Path(d).iterdir()],
        is_job_json_name=lambda name: str(name).endswith('.json'),
        read_json=read_json,
        report=lambda *a, **kw: None,
    )
    assert missing == [{'path': done / 'job1.json', 'job': {'file': 'missing.bin'}, 'file': 'missing.bin'}]


def test_stage1927_result_merge_rejects_caller_owned_listdir_without_calling_hook(tmp_path):
    class HostileListdir:
        touched = 0

        def __call__(self, _directory):  # pragma: no cover - must not be invoked
            type(self).touched += 1
            raise AssertionError("caller-owned __call__ executed")

        def __str__(self):  # pragma: no cover - must not be invoked
            type(self).touched += 1
            raise AssertionError("caller-owned __str__ executed")

    results_dir = tmp_path / "file_results"
    results_dir.mkdir()
    reports = []

    with pytest.raises(QueueResultMergeError):
        load_queue_file_results(
            tmp_path,
            file_results_dir=lambda _queue_dir: results_dir,
            safe_listdir=HostileListdir(),
            read_json=lambda _path, default=None: default,
            report=lambda *args, **kwargs: reports.append((args, kwargs)),
        )

    assert HostileListdir.touched == 0
    assert reports and reports[0][0][0] == "queue_file_result_list_failed"


def test_stage1927_done_job_merge_rejects_caller_owned_listdir_without_calling_hook(tmp_path):
    class HostileListdir:
        touched = 0

        def __call__(self, _directory):  # pragma: no cover - must not be invoked
            type(self).touched += 1
            raise AssertionError("caller-owned __call__ executed")

        def __str__(self):  # pragma: no cover - must not be invoked
            type(self).touched += 1
            raise AssertionError("caller-owned __str__ executed")

    pending = tmp_path / "pending"
    active = tmp_path / "active"
    done = tmp_path / "done"
    failed = tmp_path / "failed"
    for directory in (pending, active, done, failed):
        directory.mkdir()
    reports = []

    missing = done_jobs_missing_results(
        tmp_path,
        {},
        job_dirs=lambda _queue_dir: (pending, active, done, failed),
        safe_listdir=HostileListdir(),
        is_job_json_name=lambda name: str(name).endswith(".json"),
        read_json=lambda _path, default=None: default,
        report=lambda *args, **kwargs: reports.append((args, kwargs)),
    )

    assert HostileListdir.touched == 0
    assert reports and reports[0][0][0] == "queue_done_result_validation_failed"
    assert missing and missing[0]["queue_validation_failed"] is True
