from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.scheduler.internal.raw_queue_monitor_no_hook import (
    disk_busy_time,
    disk_busy_time_decision,
    plain_scheduler_mapping,
    plain_scheduler_mapping_decision,
    queue_dir_path,
    queue_dir_path_decision,
)
from Virus_Scan.scheduler.replay.replay_result_fields import (
    exact_replay_text,
    exact_replay_text_decision,
    replay_count_value,
    replay_count_value_decision,
    replay_mapping_items,
    replay_mapping_items_decision,
)
from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity_records import (
    memory_toxicity_affected_info,
    memory_toxicity_affected_info_decision,
    memory_toxicity_job_record_decision,
    memory_toxicity_job_record_for,
)
from Virus_Scan.scheduler.timeout.inmemory_timeout_evidence_projection import (
    attach_timeout_evidence_to_job_records,
    job_record_for_timeout_evidence,
    job_record_for_timeout_evidence_decision,
)


class HostileMapping:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("do not items")

    def get(self, key, default=None):
        type(self).touched += 1
        raise RuntimeError("do not get")


class HostileScalar:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")

    def __format__(self, spec):
        type(self).touched += 1
        raise RuntimeError("do not format")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")


class UnsupportedPath:
    pass


def _reset_hooks() -> None:
    HostileMapping.reset()
    HostileScalar.reset()


def _report_collector(events):
    def _report(*args, **kwargs):
        events.append((args, kwargs))

    return _report


def test_stage2117_raw_queue_monitor_paths_are_replayable_decisions(tmp_path) -> None:
    _reset_hooks()
    missing_mapping = plain_scheduler_mapping_decision(None, field_name="raw_queue")
    assert missing_mapping.status == "missing"
    assert missing_mapping.reason == "missing_scheduler_mapping"
    assert missing_mapping.mapping == {}
    assert plain_scheduler_mapping(None, field_name="raw_queue") == {}

    rejected_mapping = plain_scheduler_mapping_decision(HostileMapping(), field_name="raw_queue")
    assert rejected_mapping.status == "unsupported"
    assert rejected_mapping.mapping["pressure"] is False
    assert HostileMapping.touched == 0

    events = []
    missing_path = queue_dir_path_decision(None, _report_collector(events))
    assert missing_path.status == "missing"
    assert missing_path.path is None
    assert events == []
    assert queue_dir_path(None, _report_collector([])) is None

    rejected_path = queue_dir_path_decision(UnsupportedPath(), _report_collector(events))
    assert rejected_path.status == "unsupported"
    assert rejected_path.path is None
    assert events[-1][0][0] == "io_pressure_queue_dir_rejected"

    busy = disk_busy_time_decision({"busy_time": 12.5})
    assert busy.status == "accepted"
    assert busy.busy_time == 12.5
    rejected_busy = disk_busy_time_decision(HostileMapping())
    assert rejected_busy.status == "unsupported"
    assert rejected_busy.busy_time is None
    assert disk_busy_time(HostileMapping()) is None
    assert HostileMapping.touched == 0


def test_stage2117_replay_result_fields_expose_missing_and_rejected_decisions() -> None:
    unsupported_mapping = replay_mapping_items_decision(HostileMapping())
    assert unsupported_mapping.status == "unsupported"
    assert unsupported_mapping.items is None
    assert replay_mapping_items(HostileMapping()) is None
    assert HostileMapping.touched == 0

    missing_text = exact_replay_text_decision(None)
    assert missing_text.status == "missing"
    assert missing_text.reason == "missing_replay_text"
    assert missing_text.text == ""
    assert exact_replay_text(None) == ""

    rejected_text = exact_replay_text_decision(HostileScalar())
    assert rejected_text.status == "unsupported"
    assert rejected_text.text is None
    assert exact_replay_text(HostileScalar()) is None
    assert HostileScalar.touched == 0

    missing_count = replay_count_value_decision({}, "missing_count")
    assert missing_count.status == "missing"
    assert missing_count.reason == "missing_replay_count"
    assert missing_count.count == 0
    assert replay_count_value({}, "missing_count") == 0

    accepted_count = replay_count_value_decision({"count": "7"}, "count")
    assert accepted_count.status == "accepted_text"
    assert accepted_count.count == 7
    with pytest.raises(RuntimeError):
        replay_count_value({"count": "bad"}, "count")


def test_stage2117_memory_toxicity_record_lookups_are_replayable_decisions() -> None:
    missing_records = memory_toxicity_job_record_decision(None, "job-1")
    assert missing_records.status == "missing_records"
    assert missing_records.value is None
    assert memory_toxicity_job_record_for(None, "job-1") is None

    record = {"state": "running"}
    accepted = memory_toxicity_job_record_decision({"job-1": record}, "job-1")
    assert accepted.status == "accepted"
    assert accepted.value is record
    assert memory_toxicity_job_record_for({"job-1": record}, "job-1") is record

    affected_missing = memory_toxicity_affected_info_decision(active={}, job_id=None)
    assert affected_missing.status == "missing_job_id"
    assert affected_missing.value is None
    affected = memory_toxicity_affected_info_decision(active={"job-1": record}, job_id="job-1")
    assert affected.status == "accepted"
    assert affected.value is record
    assert memory_toxicity_affected_info(active={"job-1": record}, job_id="job-1") is record


def test_stage2117_timeout_evidence_projection_lookups_are_replayable_decisions() -> None:
    _reset_hooks()
    rejected_records = job_record_for_timeout_evidence_decision(HostileMapping(), HostileScalar())
    assert rejected_records.status == "unsupported_records"
    assert rejected_records.record is None
    assert job_record_for_timeout_evidence(HostileMapping(), HostileScalar()) is None
    assert HostileMapping.touched == 0
    assert HostileScalar.touched == 0

    record = {"history": ()}
    accepted = job_record_for_timeout_evidence_decision({"7": record}, 7)
    assert accepted.status == "accepted"
    assert accepted.record is record
    assert job_record_for_timeout_evidence({"7": record}, 7) is record

    attach_timeout_evidence_to_job_records(
        job_records={7: record},
        evidence_records=(
            {
                "stage": "inmemory_timeout_retry_escalation",
                "job_id": 7,
                "reason": "timeout",
                "action": "retry_or_fail",
            },
        ),
    )
    assert record["timeout_retry_evidence_recorded"] is True
    assert record["timeout_retry_evidence"][0]["job_id"] == 7


def test_stage2117_targeted_hidden_literal_returns_are_removed_from_sources() -> None:
    source_expectations = {
        Path("Virus_Scan/scheduler/internal/raw_queue_monitor_no_hook.py"): (
            "return {}",
            "return None if reason else metric",
        ),
        Path("Virus_Scan/scheduler/replay/replay_result_fields.py"): (
            "return None\n\n\ndef is_replay_mapping",
            "return 0\n\n\n__all__",
        ),
        Path("Virus_Scan/scheduler/timeout/inmemory_memory_toxicity_records.py"): (
            "return record if isinstance(record, MutableMapping) else None",
            "return info if isinstance(info, MutableMapping) else None",
        ),
        Path("Virus_Scan/scheduler/timeout/inmemory_timeout_evidence_projection.py"): (
            "return None\n\n\ndef _existing_timeout_evidence_identities",
            "return False\n    evidence_key",
        ),
    }
    for source_path, removed_markers in source_expectations.items():
        source = source_path.read_text(encoding="utf-8")
        for marker in removed_markers:
            assert marker not in source
