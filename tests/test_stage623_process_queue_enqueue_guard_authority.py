from pathlib import Path

from Virus_Scan.scheduler.queue import admission_guard as process_queue_admission
from Virus_Scan.scheduler.queue import publish as process_queue_publish
from Virus_Scan.scheduler.queue import claim as process_queue_claiming


def test_process_queue_enqueue_guard_is_owned_by_queue_admission_guard():
    assert hasattr(process_queue_admission, "process_queue_enqueue_guard")
    source = Path(process_queue_admission.__file__).read_text(encoding="utf-8")
    assert "def process_queue_enqueue_guard" in source
    assert "_queue_job_dirs(queue_dir)" in source
    assert "queue_is_job_json_name" in source


def test_claim_publish_recovery_import_enqueue_guard_from_process_queue_admission():
    for module in (process_queue_claiming, process_queue_publish):
        source = Path(module.__file__).read_text(encoding="utf-8")
        assert "process_queue_enqueue_guard as _queue_enqueue_guard" in source
        assert "    enqueue_guard as _queue_enqueue_guard" not in source


def test_scheduler_identity_no_longer_used_as_process_queue_guard_source():
    for module in (process_queue_claiming, process_queue_publish):
        source = Path(module.__file__).read_text(encoding="utf-8")
        assert "from Virus_Scan.scheduler.ownership.scheduler_identity import" not in source
        assert "process_queue_enqueue_guard" in source
        assert "from Virus_Scan.scheduler.ownership.queue_identity import" not in source
