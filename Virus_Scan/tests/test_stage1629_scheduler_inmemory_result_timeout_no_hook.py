from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.evidence.inmemory_result_timeout import attach_inmemory_result_evidence


class HostileTruthTextIntSequence:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call bool")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not call str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not call repr")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("do not call int")

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("do not call float")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not call iter")


def _capture_attacher(calls):
    def _attach(enriched, path, **kwargs):
        calls.append((enriched, path, kwargs))
        return {"attached": True, "enriched": enriched, "kwargs": kwargs}

    return _attach


def test_stage1629_inmemory_result_timeout_rejects_hostile_record_values_without_hooks():
    hostile = HostileTruthTextIntSequence()
    HostileTruthTextIntSequence.touched = 0
    calls = []

    result = attach_inmemory_result_evidence(
        result={"tags": (), "trusted_benign": False},
        record={
            "last_heartbeat": hostile,
            "last_progress_time": hostile,
            "stage": hostile,
            "progress_counter": hostile,
            "bytes_processed": hostile,
            "pid": hostile,
        },
        path="sample.bin",
        worker_pid=hostile,
        container_root="root",
        evidence_context={"source": "test"},
        routing_evidence_attacher=_capture_attacher(calls),
        wall_time=lambda: 100.0,
    )

    assert result["attached"] is True
    assert HostileTruthTextIntSequence.touched == 0
    timeout_evidence = calls[0][0]["timeout_evidence"]
    assert timeout_evidence["current_stage"] == "scan"
    assert timeout_evidence["progress_counter"] == 0
    assert timeout_evidence["bytes_processed"] == 0
    assert timeout_evidence["worker_pid"] == 0
    reasons = {item["reason"] for item in timeout_evidence["scheduler_timeout_input_rejections"]}
    assert "unsafe_last_heartbeat" in reasons
    assert "unsafe_last_progress_time" in reasons
    assert "unsafe_progress_counter" in reasons
    assert "unsafe_bytes_processed" in reasons
    assert "unsafe_worker_pid" in reasons
    assert "unsafe_text_value_rejected" in reasons


def test_stage1629_inmemory_result_timeout_rejects_hostile_result_truthiness_and_tags():
    hostile = HostileTruthTextIntSequence()
    HostileTruthTextIntSequence.touched = 0
    calls = []

    attach_inmemory_result_evidence(
        result={
            "tags": hostile,
            "trusted_benign": hostile,
            "error": hostile,
            "timeout_evidence": {"worker_state": "queue_worker_alive_progressing"},
        },
        record={"last_heartbeat": 99.0, "last_progress_time": 99.0, "stage": "scan"},
        path="sample.bin",
        worker_pid=123,
        container_root="root",
        evidence_context=None,
        routing_evidence_attacher=_capture_attacher(calls),
        wall_time=lambda: 100.0,
    )

    assert HostileTruthTextIntSequence.touched == 0
    enriched, _path, kwargs = calls[0]
    assert kwargs["tags"] == ()
    assert kwargs["trusted_benign"] is False
    assert kwargs["degraded"] is True
    rejection_fields = {item["field"] for item in enriched["timeout_evidence"]["scheduler_timeout_input_rejections"]}
    assert {"tags", "trusted_benign", "error"}.issubset(rejection_fields)


def test_stage1629_inmemory_result_timeout_preserves_valid_timeout_evidence_behavior():
    calls = []

    result = attach_inmemory_result_evidence(
        result={"tags": ("a", "b"), "trusted_benign": "true", "timed_out": "true"},
        record={"last_heartbeat": 90.0, "last_progress_time": 95.0, "stage": "scan", "progress_counter": "7", "bytes_processed": "42", "pid": "123"},
        path="sample.bin",
        worker_pid=999,
        container_root="root",
        evidence_context={"source": "test"},
        routing_evidence_attacher=_capture_attacher(calls),
        wall_time=lambda: 100.0,
    )

    assert result["attached"] is True
    enriched, _path, kwargs = calls[0]
    assert enriched["timeout_evidence"]["heartbeat_age"] == 10.0
    assert enriched["timeout_evidence"]["progress_age"] == 5.0
    assert enriched["timeout_evidence"]["current_stage"] == "scan"
    assert enriched["timeout_evidence"]["progress_counter"] == 7
    assert enriched["timeout_evidence"]["bytes_processed"] == 42
    assert enriched["timeout_evidence"]["worker_pid"] == 123
    assert kwargs["tags"] == ("a", "b")
    assert kwargs["trusted_benign"] is True
    assert kwargs["degraded"] is True


def test_stage1836_inmemory_result_timeout_rejects_hostile_scalars_with_owned_reasons():
    hostile = HostileTruthTextIntSequence()
    HostileTruthTextIntSequence.touched = 0
    calls = []

    attach_inmemory_result_evidence(
        result={"tags": (), "trusted_benign": False},
        record={
            "last_heartbeat": hostile,
            "last_progress_time": hostile,
            "stage": hostile,
            "progress_counter": hostile,
            "bytes_processed": hostile,
            "pid": hostile,
        },
        path="sample.bin",
        worker_pid=hostile,
        container_root="root",
        evidence_context={"source": "test"},
        routing_evidence_attacher=_capture_attacher(calls),
        wall_time=lambda: 100.0,
    )

    assert HostileTruthTextIntSequence.touched == 0
    reasons = {item["reason"] for item in calls[0][0]["timeout_evidence"]["scheduler_timeout_input_rejections"]}
    assert "unsafe_last_heartbeat" in reasons
    assert "unsafe_last_progress_time" in reasons
    assert "unsafe_progress_counter" in reasons
    assert "unsafe_bytes_processed" in reasons
    assert "unsafe_worker_pid" in reasons


def test_stage1836_inmemory_result_timeout_source_uses_owned_timeout_contracts():
    source_root = Path(__file__).resolve().parents[1] / "scheduler" / "evidence"
    source = (source_root / "inmemory_result_timeout.py").read_text(encoding="utf-8")
    support = (source_root / "inmemory_result_timeout_support.py").read_text(encoding="utf-8")

    assert "safe_float" not in source
    assert "safe_int" not in source
    assert "safe_text" not in source
    assert "safe_bool" not in source
    assert "safe_mapping" not in source
    assert "safe_tags" not in source
    assert "default=" not in source
    assert "timeout_float(" in source
    assert "timeout_int(" in source
    assert "timeout_text(" in source
    assert "timeout_bool(" in source
    assert "timeout_mapping(" in source
    assert "timeout_tags(" in source
    assert "def safe_float" not in support
    assert "def safe_int" not in support
    assert "def safe_text" not in support
    assert 'f"{field}_' not in support
    assert 'str.__add__("unsafe_", field)' in support
    assert "_timeout_field_key(field," in support
