from Virus_Scan.scheduler.evidence.final_json_status_sources import checkpoint_status_from_record


class HostileSchedulerCheckpointRecord:
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


class HostileCheckpointReference:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("reference str must not execute")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("reference repr must not execute")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("reference iter must not execute")


def test_stage1730_empty_checkpoint_status_container_returns_evidence_not_empty_dict():
    status = checkpoint_status_from_record({"checkpoint_status": {}}, None)

    assert status != {}
    assert status["failed"] is True
    assert status["empty_scheduler_status"] is True
    assert status["reason"] == "scheduler_status_empty_container"
    assert status["final_json_must_record"] is True
    assert status["checkpoint_must_record"] is True


def test_stage1730_empty_scheduler_checkpoint_list_returns_evidence_not_empty_dict():
    status = checkpoint_status_from_record({"scheduler_checkpoint": []}, None)

    assert status != {}
    assert status["failed"] is True
    assert status["empty_scheduler_status"] is True
    assert status["value_type"] == "list"


def test_stage1730_unsupported_checkpoint_status_source_rejected_without_hooks():
    HostileSchedulerCheckpointRecord.touched = 0

    status = checkpoint_status_from_record(HostileSchedulerCheckpointRecord(), None)

    assert HostileSchedulerCheckpointRecord.touched == 0
    assert status != {}
    assert status["scheduler_status_source_failed"] is True
    assert status["reason"] == "unsupported_checkpoint_status_source"
    assert status["unsupported_scheduler_value"] is True
    assert status["final_json_must_record"] is True


def test_stage1730_absent_checkpoint_status_on_exact_record_remains_legitimate_empty_result():
    assert checkpoint_status_from_record({}, None) == {}


def test_stage1730_canonical_empty_checkpoint_placeholder_remains_legitimate_empty_result():
    assert checkpoint_status_from_record({"checkpoint": {}}, None) == {}


def test_stage1730_hostile_checkpoint_reference_is_evidence_not_stringified():
    HostileCheckpointReference.touched = 0

    status = checkpoint_status_from_record({"checkpoint_reference": HostileCheckpointReference()}, None)

    assert HostileCheckpointReference.touched == 0
    assert status != {}
    assert status["failed"] is True
    assert status["error_category"] == "scheduler_checkpoint_reference_unsupported"
    assert status["unsupported_checkpoint_references"]["checkpoint_reference"]["unsupported_scheduler_value"] is True
