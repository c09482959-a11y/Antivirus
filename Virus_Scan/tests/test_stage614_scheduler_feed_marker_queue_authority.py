import inspect

from Virus_Scan.scheduler.orchestration import process_queue_monitor_scaling_feed
from Virus_Scan.scheduler.orchestration import process_queue_startup_admission
from Virus_Scan.scheduler.queue import claim as process_queue_claiming
from Virus_Scan.scheduler.queue import feed_marker as queue_feed_marker


def test_feed_marker_authority_not_exported_by_claiming():
    assert not hasattr(process_queue_claiming, "_mark_process_queue_feed_complete")
    assert not hasattr(process_queue_claiming, "_process_queue_feed_is_complete")


def test_feed_marker_authority_imported_from_queue_authority():
    assert process_queue_startup_admission._mark_process_queue_feed_complete is queue_feed_marker.mark_process_queue_feed_complete
    assert process_queue_monitor_scaling_feed._mark_process_queue_feed_complete is queue_feed_marker.mark_process_queue_feed_complete
    assert queue_feed_marker.mark_process_queue_feed_complete.__module__.endswith("queue.feed_marker")
    assert queue_feed_marker.process_queue_feed_is_complete.__module__.endswith("queue.feed_marker")


def test_process_queue_support_no_longer_owns_os_pid_or_feed_marker_alias():
    source = inspect.getsource(process_queue_startup_admission) + inspect.getsource(process_queue_monitor_scaling_feed)
    assert "queue.claim import _mark_process_queue_feed_complete" not in source
    assert "process_queue_support" not in source
