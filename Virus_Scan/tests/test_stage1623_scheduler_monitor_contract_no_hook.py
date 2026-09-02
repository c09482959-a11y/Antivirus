from pathlib import Path

from Virus_Scan.scheduler.internal.live_path_entries import freeze_live_scheduler_path
from Virus_Scan.scheduler.orchestration.process_queue_monitor_contracts import (
    ProcessQueueMonitorLoopRequest,
    ProcessQueueMonitorLoopResult,
)


class HostileMonitorValue:
    touched = 0

    @classmethod
    def reset(cls):
        cls.touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify scheduler monitor value")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr scheduler monitor value")

    def __format__(self, _spec):
        type(self).touched += 1
        raise RuntimeError("do not format scheduler monitor value")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("do not int scheduler monitor value")

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("do not float scheduler monitor value")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool scheduler monitor value")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate scheduler monitor value")


class DummyWorkerPool:
    pass


def test_stage1623_monitor_loop_request_rejects_hostile_paths_scalars_and_identities_without_hooks():
    HostileMonitorValue.reset()
    hostile = HostileMonitorValue()

    request = ProcessQueueMonitorLoopRequest(
        queue_dir=Path("queue"),
        outputs_dir=Path("outputs"),
        worker_pool=DummyWorkerPool(),
        all_files=["safe.bin", hostile],
        ordered_queue_items=(("job", 0, {"file": "safe.bin"}),),
        queue_feed_cursor=hostile,
        queue_enqueued_identities=["job-a", hostile],
        queue_total_enqueued=hostile,
        queue_last_feed_log=hostile,
        raw_stage_progress_state=None,
        process_count=hostile,
        requested_process_count=hostile,
        dynamic_queue_feed=hostile,
        elastic_scheduler=hostile,
        next_worker_spawn_id=hostile,
        progress_every=hostile,
        partial_output_path=None,
        per_file_timeout_sec=hostile,
    )

    assert HostileMonitorValue.touched == 0
    assert request.all_files[0] == "safe.bin"
    assert request.all_files[1]["unsupported_scheduler_value"] is True
    assert request.all_files[1]["field_name"] == "scheduler_path"
    assert request.queue_enqueued_identities == frozenset({"job-a", "unsupported_queue_identity_1"})
    assert request.queue_feed_cursor == 0
    assert request.queue_total_enqueued == 0
    assert request.queue_last_feed_log == 0.0
    assert request.process_count == 0
    assert request.requested_process_count == 0
    assert request.dynamic_queue_feed is False
    assert request.elastic_scheduler is False
    assert request.next_worker_spawn_id == 0
    assert request.progress_every == 1
    assert request.per_file_timeout_sec == 0.0


def test_stage1623_monitor_loop_result_rejects_hostile_had_error_without_bool_hook():
    HostileMonitorValue.reset()
    result = ProcessQueueMonitorLoopResult(had_error=HostileMonitorValue())

    assert HostileMonitorValue.touched == 0
    assert result.had_error is False


def test_stage1623_live_scheduler_path_rejects_unknown_path_object_without_string_hooks():
    HostileMonitorValue.reset()
    materialized = freeze_live_scheduler_path(HostileMonitorValue())

    assert HostileMonitorValue.touched == 0
    assert materialized["unsupported_scheduler_value"] is True
    assert materialized["field_name"] == "scheduler_path"
