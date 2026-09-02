import os

from Virus_Scan.scheduler.runtime.queue_json import read_json_file as _queue_read_json_file, make_json_safe
from Virus_Scan.core.logging import queue_safe_unlink
from Virus_Scan.scheduler.queue import claim_sidecar_policy as raw_claims
from Virus_Scan.scheduler.queue.authority import queue_now


def test_raw_queue_core_dependencies_are_explicit_imports():
    assert callable(_queue_read_json_file)
    assert callable(make_json_safe)
    assert callable(queue_safe_unlink)
    assert _queue_read_json_file is _queue_read_json_file


def test_claim_sidecar_failure_reports_without_undefined_pid(tmp_path):
    seen = []

    def fail_write(*args, **kwargs):
        raise OSError("forced sidecar write failure")

    def record(stage, exc, **kwargs):
        seen.append((stage, type(exc).__name__, kwargs))

    ok = raw_claims.write_claim_sidecar_from_job(
        tmp_path / "active.json",
        {"file": "sample.bin"},
        now=queue_now,
        pid=os.getpid,
        write_claim_meta=fail_write,
        report=record,
        os_fspath=os.fspath,
    )

    assert ok is False
    assert seen
    assert seen[0][0] == "queue_claim_sidecar_write_failed"
    assert seen[0][2].get("fatal") is True
