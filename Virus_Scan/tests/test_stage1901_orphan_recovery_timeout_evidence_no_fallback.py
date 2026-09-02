from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.scheduler.queue.orphan_recovery_timeout_evidence import (
    job_mapping,
    resolve_reclaim_float_value,
    resolve_reclaim_int_value,
)


class HostileValue:
    touched = 0

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("do not float")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("do not int")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iter")


def test_stage1901_timeout_policy_evidence_uses_default_value_without_hooks():
    HostileValue.touched = 0
    evidence = []
    hostile = HostileValue()

    resolved = resolve_reclaim_float_value(value=hostile, field="stage1901_float", default_value=7.5, evidence=evidence)

    assert resolved == 7.5
    assert HostileValue.touched == 0
    record = evidence[0]
    assert record["reason"] == "stage1901_float_malformed"
    assert record["raw_value_preview"] == "<HostileValue>"
    assert record["default_value"] == 7.5
    assert "fallback_value" not in record
    assert record["error_source"] == "orphan_recovery_timeout.stage1901_float"


def test_stage1901_timeout_int_and_job_mapping_default_evidence_without_hooks():
    HostileValue.touched = 0
    evidence = []
    hostile = HostileValue()

    assert resolve_reclaim_int_value(value=hostile, field="stage1901_int", default_value=4, evidence=evidence) == 4
    mapping = job_mapping(hostile, evidence)

    assert HostileValue.touched == 0
    reasons = [record["reason"] for record in evidence]
    assert "stage1901_int_malformed" in reasons
    assert "job_record_malformed" in reasons
    assert mapping["job_record_unavailable"] is True
    for record in evidence:
        assert "fallback_value" not in record
        assert "default_value" in record


def test_stage1901_timeout_evidence_source_has_no_fallback_or_fstring_routes():
    source = read_python_file(Path("Virus_Scan/scheduler/queue/orphan_recovery_timeout_evidence.py"))

    assert "fallback_value" not in source
    assert 'f"{self.field}_malformed"' not in source
    assert 'f"<{no_hook_type_name(value)}>"' not in source
    assert 'f"orphan_recovery_timeout.{owned_field}"' not in source
    assert "def safe_reclaim_float" not in source
    assert "def safe_reclaim_int" not in source
