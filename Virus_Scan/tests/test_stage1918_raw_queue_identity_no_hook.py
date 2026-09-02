from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path


import pytest

from Virus_Scan.scheduler.api.contracts import QueueIdentityScanError
from Virus_Scan.scheduler.queue import raw_queue_identity

SOURCE = Path("Virus_Scan/scheduler/queue/raw_queue_identity.py")


class HostileValue:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("str hook must not execute")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("repr hook must not execute")

    def __format__(self, spec):
        type(self).touched += 1
        raise RuntimeError("format hook must not execute")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("bool hook must not execute")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("iter hook must not execute")

    def __fspath__(self):
        type(self).touched += 1
        raise RuntimeError("fspath hook must not execute")


class HostileError(RuntimeError):
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("exception str hook must not execute")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("exception repr hook must not execute")

    def __format__(self, spec):
        type(self).touched += 1
        raise RuntimeError("exception format hook must not execute")


def _job_dirs(queue_dir):
    base = Path(queue_dir)
    return base / "pending", base / "active", base / "done", base / "failed"


def test_stage1918_identity_ttl_policy_failure_reports_without_exception_hooks():
    HostileError.touched = 0
    reports = []

    def failing_float_env(*_args):
        raise HostileError("hostile ttl")

    ttl = raw_queue_identity._queue_identity_index_ttl_sec(
        float_env_func=failing_float_env,
        report_issue=lambda where, exc: reports.append((where, type(exc).__name__)),
    )

    assert ttl == 2.0
    assert reports == [("queue_identity_index_ttl_policy_unavailable", "HostileError")]
    assert HostileError.touched == 0


def test_stage1918_collect_existing_identities_filters_states_names_and_maps_without_hooks(tmp_path):
    HostileValue.touched = 0
    pending, active, done, failed = _job_dirs(tmp_path)
    quarantine = tmp_path / "quarantine"
    file_results = tmp_path / "file_results"
    for directory in (pending, active, done, failed, quarantine, file_results):
        directory.mkdir(parents=True, exist_ok=True)

    def safe_listdir(directory):
        if Path(directory) == pending:
            return [HostileValue(), "pending-job.json"]
        if Path(directory) == file_results:
            return [HostileValue(), "sample.result.json"]
        return []

    def read_json(path, default=None):
        name = Path(path).name
        if name == "sample.result.json":
            return {"file": "sample.bin"}
        return {"file_id": "fid", "seq": 1}

    found = raw_queue_identity.collect_existing_identities(
        tmp_path,
        states=(HostileValue(), "pending", "file_results"),
        job_dirs=_job_dirs,
        quarantine_dir=lambda queue_dir: Path(queue_dir) / "quarantine",
        file_results_dir=lambda queue_dir: Path(queue_dir) / "file_results",
        safe_listdir=safe_listdir,
        is_job_json_name=lambda name: name.endswith(".json"),
        read_json=read_json,
        job_identity=lambda job, name=None: "identity:" + (job.get("file") or job.get("file_id")),
        identity_index_get=lambda *_args, **_kwargs: None,
        identity_index_set=lambda *_args, **_kwargs: None,
    )

    assert found == {"identity:fid", "identity:sample.bin"}
    assert HostileValue.touched == 0


def test_stage1918_collect_existing_identities_strict_failure_uses_projected_exception_text(tmp_path):
    HostileError.touched = 0
    log_messages = []
    reports = []

    with pytest.raises(QueueIdentityScanError) as raised:
        raw_queue_identity.collect_existing_identities(
            tmp_path,
            strict=True,
            job_dirs=lambda _queue_dir: (_ for _ in ()).throw(HostileError("scan denied")),
            quarantine_dir=lambda queue_dir: Path(queue_dir) / "quarantine",
            file_results_dir=lambda queue_dir: Path(queue_dir) / "file_results",
            safe_listdir=lambda _directory: [],
            is_job_json_name=lambda _name: False,
            read_json=lambda _path, default=None: {},
            job_identity=lambda _job, _name=None: "unused",
            identity_index_get=lambda *_args, **_kwargs: None,
            identity_index_set=lambda *_args, **_kwargs: None,
            log_error=log_messages.append,
            report=lambda where, exc, **kwargs: reports.append((where, type(exc).__name__, kwargs.get("fatal"))),
        )

    assert HostileError.touched == 0
    assert "scheduler diagnostic detail unavailable without caller hooks" in BaseException.__str__(raised.value)
    assert log_messages == [
        "queue existing-identity scan failed: HostileError: scheduler diagnostic detail unavailable without caller hooks"
    ]
    assert reports == [("queue_existing_identity_scan_failed", "HostileError", True)]


def test_stage1918_raw_queue_identity_source_closes_unsafe_identity_routes():
    source = read_python_file(SOURCE)

    assert "return None\n\n\ndef _queue_identity_index_ttl_sec" not in source
    assert "queue_identity_index_ttl_policy_fallback" not in source
    assert "str(name).endswith" not in source
    assert "rec.get(\"file\")" not in source
    assert "state_dirs.get(str(state))" not in source
    assert "if not d:" not in source
    assert "if type(job) is dict:" not in source
    assert "log_error(f\"queue existing-identity scan failed: {exc}\")" not in source
    assert "QueueIdentityScanError(str(exc))" not in source
