from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.scheduler.workers.process_queue_child_job import ProcessQueueChildJobRequest



def test_process_queue_child_job_uses_injected_progress_and_raw_stage_dependencies():
    fields = getattr(ProcessQueueChildJobRequest, "__dataclass_fields__")
    assert "execute_raw_stage_job" in fields
    assert "bulk_scan_maintenance" in fields
    assert "log_bulk_progress" in fields
    assert "sleep" in fields
    assert "log_error" in fields
    assert "record_heartbeat_failure" in fields

    text = read_python_file(Path("Virus_Scan/scheduler/workers/process_queue_child_job.py"))
    assert "from Virus_Scan.core.cache" not in text
    assert "from Virus_Scan.core.logging" not in text
    assert "execute_inmemory_raw_stage_job" not in text
    assert "time.sleep" not in text
    assert "runtime.scan_dependencies" not in text
    assert "runtime.structured_failures" not in text
