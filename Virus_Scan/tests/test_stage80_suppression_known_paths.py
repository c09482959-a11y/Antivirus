import json
import inspect
from pathlib import Path


from Virus_Scan.scheduler.runtime.queue_json import _queue_write_json_replace
from Virus_Scan.scheduler.runtime.queue_json_replace_tmp import queue_json_write_tmp_payload

def test_queue_json_replace_has_one_canonical_flush_path():
    parameters = inspect.signature(queue_json_write_tmp_payload).parameters
    source = inspect.getsource(queue_json_write_tmp_payload)

    assert "os_fsync" not in parameters
    assert "flush_open_writable_file(handle.fileno())" in source


def test_queue_json_replace_publishes_schema_normalized_record_on_success(tmp_path):

    target = tmp_path / "job.json"
    ok = _queue_write_json_replace(target, {"job_type": "raw"}, verify=True)
    assert ok is True
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["job_type"] == "raw"
    assert data["schema_version"] == 1
