from __future__ import annotations

from Virus_Scan.scheduler.orchestration.inmemory_parent_runtime_setup import _attach_timeout_config_evidence_to_job_records
from Virus_Scan.scheduler.timeout.inmemory_timeout_config import build_inmemory_timeout_config


class HostileJobRecords:
    touched = 0

    def __getattribute__(self, name):
        if name == "items":
            type(self).touched += 1
            raise RuntimeError("do not touch job_records.items")
        return object.__getattribute__(self, name)

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate job records")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool job records")


class HostileEvidenceRecord:
    touched = 0

    def __getattribute__(self, name):
        if name in {"items", "get"}:
            type(self).touched += 1
            raise RuntimeError("do not touch evidence mapping hooks")
        return object.__getattribute__(self, name)

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate evidence")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr evidence")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not str evidence")


class HostileExistingHistory:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool existing history")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate existing history")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr existing history")


def test_stage1610_timeout_config_attachment_rejects_hostile_job_records_without_hooks():
    HostileJobRecords.touched = 0
    config = build_inmemory_timeout_config(
        {"UMIGE_INMEMORY_CANCEL_GRACE_SEC": "bad-cancel"},
        per_file_timeout_sec=20,
    )

    _attach_timeout_config_evidence_to_job_records(HostileJobRecords(), tuple(config.config_evidence))

    assert HostileJobRecords.touched == 0


def test_stage1610_timeout_config_attachment_rejects_hostile_evidence_without_hooks():
    HostileEvidenceRecord.touched = 0
    job_records = {0: {"history": (), "state": "pending"}}

    _attach_timeout_config_evidence_to_job_records(job_records, (HostileEvidenceRecord(),))

    assert HostileEvidenceRecord.touched == 0
    evidence = job_records[0]["timeout_config_evidence"][0]
    assert evidence["scheduler_mapping_unavailable"] is True
    assert evidence["reason"] == "non_materializable_scheduler_mapping"
    assert job_records[0]["history"][-1]["action"] == "timeout_config_evidence"
    assert job_records[0]["history"][-1]["timeout_config_evidence"]["scheduler_mapping_unavailable"] is True


def test_stage1610_timeout_config_attachment_rejects_hostile_existing_history_without_hooks():
    HostileExistingHistory.touched = 0
    config = build_inmemory_timeout_config(
        {"UMIGE_INMEMORY_CANCEL_GRACE_SEC": "bad-cancel"},
        per_file_timeout_sec=20,
    )
    job_records = {0: {"history": HostileExistingHistory(), "state": "pending"}}

    _attach_timeout_config_evidence_to_job_records(job_records, tuple(config.config_evidence))

    assert HostileExistingHistory.touched == 0
    assert job_records[0]["history"][0]["unsupported_scheduler_value"] is True
    assert job_records[0]["history"][0]["field_name"] == "existing_job_history"
    assert job_records[0]["history"][-1]["action"] == "timeout_config_evidence"
    assert job_records[0]["timeout_config_evidence"][0]["setting"] == "UMIGE_INMEMORY_CANCEL_GRACE_SEC"
