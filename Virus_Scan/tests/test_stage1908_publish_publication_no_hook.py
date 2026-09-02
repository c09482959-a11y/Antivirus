from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path


import pytest

from Virus_Scan.scheduler.queue.publish import _queue_dir_failure_message
from Virus_Scan.scheduler.queue.publish_controls import process_queue_publish_result_tuple
from Virus_Scan.scheduler.queue.publish_controls import normalize_publish_attempt_result, record_publish_summary
from Virus_Scan.scheduler.queue.publish_job_contract import ProcessQueuePublishResult


class HostileValue:
    def __bool__(self):
        raise AssertionError("bool hook executed")

    def __str__(self):
        raise AssertionError("str hook executed")

    def __format__(self, spec):
        raise AssertionError("format hook executed")

    def __fspath__(self):
        raise AssertionError("fspath hook executed")


def test_publish_result_tuple_uses_exact_contract_bools_without_bool_hooks():
    assert process_queue_publish_result_tuple(ProcessQueuePublishResult(published=False, guard_blocked=True)) == (
        False,
        True,
        False,
    )
    assert process_queue_publish_result_tuple(HostileValue()) == (False, False, True)


def test_publish_queue_dir_failure_message_rejects_hostile_path_without_hooks():
    message = _queue_dir_failure_message(HostileValue())
    assert message.startswith("could not create process queue directories: <HostileValue unsupported_process_queue_dir")


def test_publish_attempt_result_flags_reject_hostile_values_without_bool_hooks():
    suppressed = []
    result = normalize_publish_attempt_result(
        (False, HostileValue(), False),
        record_suppressed=lambda stage, exc, **extra: suppressed.append((stage, str(exc), extra)),
    )
    assert result == (False, False, True)
    assert suppressed[0][0] == "process_queue_publish_attempt_result_rejected"
    assert suppressed[0][1] == "process_queue_publish_attempt_flag_1_rejected"


def test_publish_controls_source_has_no_repaired_fstrings_or_fallback_routes():
    publish_source = read_python_file(Path("Virus_Scan/scheduler/queue/publish.py"))
    controls_source = read_python_file(Path("Virus_Scan/scheduler/queue/publish_controls.py"))
    forbidden = (
        'return False, bool(outcome.guard_blocked), bool(outcome.guard_exception or outcome.durable_write_failed)',
        'f"could not create process queue directories: {queue_dir}"',
        'fallback=0',
        'f"process_queue_publish_attempt_flag_{index}_rejected"',
        'RuntimeError(f"failed_queue_job_publishes={failed_publishes}")',
    )
    joined = publish_source + controls_source
    for pattern in forbidden:
        assert pattern not in joined


def test_record_publish_summary_uses_owned_failure_text():
    suppressed = []
    record_publish_summary(0, 3, record_suppressed=lambda stage, exc, **_extra: suppressed.append((stage, str(exc))))
    assert suppressed == [("queue_enqueue_publish_failed", "failed_queue_job_publishes=3")]
