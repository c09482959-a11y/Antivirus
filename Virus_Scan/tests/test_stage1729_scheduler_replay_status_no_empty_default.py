from Virus_Scan.scheduler.evidence.final_json_status_sources import replay_status_from_record


class HostileSchedulerRecord:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("record iter must not execute")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("record len must not execute")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("record str must not execute")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("record repr must not execute")


def test_stage1729_empty_replay_status_container_returns_evidence_not_empty_dict():
    status = replay_status_from_record({"replay_status": {}}, None)

    assert status != {}
    assert status["failed"] is True
    assert status["empty_scheduler_status"] is True
    assert status["reason"] == "scheduler_status_empty_container"
    assert status["final_json_must_record"] is True
    assert status["replay_must_record"] is True


def test_stage1729_empty_scheduler_replay_list_returns_evidence_not_empty_dict():
    status = replay_status_from_record({"scheduler_replay": []}, None)

    assert status != {}
    assert status["failed"] is True
    assert status["empty_scheduler_status"] is True
    assert status["value_type"] == "list"


def test_stage1729_unsupported_replay_status_source_rejected_without_hooks():
    HostileSchedulerRecord.touched = 0

    status = replay_status_from_record(HostileSchedulerRecord(), None)

    assert HostileSchedulerRecord.touched == 0
    assert status != {}
    assert status["scheduler_status_source_failed"] is True
    assert status["reason"] == "unsupported_replay_status_source"
    assert status["unsupported_scheduler_value"] is True
    assert status["final_json_must_record"] is True


def test_stage1729_absent_replay_status_on_exact_record_remains_legitimate_empty_result():
    assert replay_status_from_record({}, None) == {}
