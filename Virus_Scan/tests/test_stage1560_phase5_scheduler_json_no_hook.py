"""Stage 1560 Phase 5 scheduler JSON/materialization no-hook tests."""
from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path

import pytest

from Virus_Scan.scheduler.evidence.final_json_fields import build_final_json_scheduler_fields
from Virus_Scan.scheduler.evidence.final_json_contract_support import mapping_from_scheduler_value
from Virus_Scan.scheduler.evidence.final_json_contract_projection import failure_records_from_scheduler_contract_status
from Virus_Scan.scheduler.evidence.final_json_checkpoint_projection import failure_record_from_checkpoint_status
from Virus_Scan.scheduler.evidence.final_json_compact_error_projection import build_final_json_compact_error_section
from Virus_Scan.scheduler.evidence.final_json_evidence_mapping import collect_scheduler_evidence_values_from_mapping
from Virus_Scan.scheduler.evidence.final_json_exact_fields import exact_mapping_items, first_exact_text
from Virus_Scan.scheduler.evidence.final_json_failure_projection import failure_record_from_scheduler_result
from Virus_Scan.scheduler.evidence.final_json_passive_scalar import scalar_failure_category
from Virus_Scan.scheduler.evidence.final_json_projection import build_final_json_scheduler_section
from Virus_Scan.scheduler.evidence.final_json_queue_projection import failure_records_from_queue_status
from Virus_Scan.scheduler.evidence.final_json_replay_projection import failure_record_from_replay_status
from Virus_Scan.scheduler.evidence.final_json_scheduler_result_projection import failure_records_from_scheduler_result_status
from Virus_Scan.scheduler.evidence.final_json_scheduler_status_projection import failure_record_from_existing_scheduler_section
from Virus_Scan.scheduler.evidence.final_json_trace_projection import failure_records_from_trace_status
from Virus_Scan.scheduler.replay.replay_projection import (
    canonical_replay_sequence,
    queue_replay_result_file_identity,
    queue_replay_result_job_identity,
    replay_result_evidence,
)
from Virus_Scan.scheduler.replay.replay_validator import QueueReplayComparisonRecord
from Virus_Scan.scheduler.runtime.queue_json_safety import make_json_safe


class HostileText:
    str_calls = 0
    repr_calls = 0

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("str hook called")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("repr hook called")


class HostileIterable:
    iter_calls = 0

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("iter hook called")


class HostileMapping(Mapping):
    items_calls = 0

    def __getitem__(self, key):
        raise KeyError(key)

    def __iter__(self):
        raise RuntimeError("mapping iter hook called")

    def __len__(self):
        raise RuntimeError("mapping len hook called")

    def items(self):
        type(self).items_calls += 1
        raise RuntimeError("mapping items hook called")


class HostileAsDict:
    property_calls = 0
    method_calls = 0

    @property
    def as_dict(self):
        type(self).property_calls += 1

        def _inner():
            type(self).method_calls += 1
            raise RuntimeError("as_dict hook called")

        return _inner


class HostileScalar:
    str_calls = 0
    repr_calls = 0
    bool_calls = 0
    eq_calls = 0

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("str hook called")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("repr hook called")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("bool hook called")

    def __eq__(self, other):
        type(self).eq_calls += 1
        raise RuntimeError("eq hook called")


def _reset_hostile_scalar() -> None:
    HostileScalar.str_calls = 0
    HostileScalar.repr_calls = 0
    HostileScalar.bool_calls = 0
    HostileScalar.eq_calls = 0


class HostileStrSubclass(str):
    len_calls = 0
    str_calls = 0
    repr_calls = 0

    def __new__(cls):
        return str.__new__(cls, "hostile")

    def __len__(self):
        type(self).len_calls += 1
        raise RuntimeError("len hook called")

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("str hook called")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("repr hook called")


def test_stage1560_scheduler_json_materializer_does_not_call_str_or_repr() -> None:
    HostileText.str_calls = 0
    HostileText.repr_calls = 0

    safe = make_json_safe({"bad": HostileText()})

    assert safe["bad"]["unsupported_scheduler_value"] is True
    assert safe["bad"]["error_category"] == "scheduler_json_materialization_unsupported"
    assert HostileText.str_calls == 0
    assert HostileText.repr_calls == 0


def test_stage1560_scheduler_json_materializer_rejects_str_subclass_without_hooks() -> None:
    HostileStrSubclass.len_calls = 0
    HostileStrSubclass.str_calls = 0
    HostileStrSubclass.repr_calls = 0

    safe = make_json_safe({"bad": HostileStrSubclass()})

    assert safe["bad"]["unsupported_scheduler_value"] is True
    assert safe["bad"]["error_category"] == "scheduler_json_materialization_unsupported"
    assert HostileStrSubclass.len_calls == 0
    assert HostileStrSubclass.str_calls == 0
    assert HostileStrSubclass.repr_calls == 0


def test_stage1560_scheduler_json_materializer_does_not_call_iterable_hooks() -> None:
    HostileIterable.iter_calls = 0

    safe = make_json_safe({"bad": HostileIterable()})

    assert safe["bad"]["unsupported_scheduler_value"] is True
    assert HostileIterable.iter_calls == 0


def test_stage1560_scheduler_json_materializer_does_not_call_mapping_items() -> None:
    HostileMapping.items_calls = 0

    safe = make_json_safe({"bad": HostileMapping()})

    assert safe["bad"]["unsupported_scheduler_value"] is True
    assert HostileMapping.items_calls == 0


def test_stage1560_scheduler_status_mapping_does_not_call_as_dict_hook() -> None:
    HostileAsDict.property_calls = 0
    HostileAsDict.method_calls = 0

    status = mapping_from_scheduler_value(HostileAsDict())

    assert status["unsupported_scheduler_value"] is True
    assert HostileAsDict.property_calls == 0
    assert HostileAsDict.method_calls == 0


def test_stage1560_unsupported_scheduler_value_is_json_and_replay_safe() -> None:
    status = mapping_from_scheduler_value(HostileText())
    json.dumps(status, sort_keys=True)

    record = {"scheduler_failure_evidence": [status]}
    fields = build_final_json_scheduler_fields(record)
    replay_tokens = replay_result_evidence(record)

    assert fields["scheduler_failure_evidence"][0]["error_category"] == "scheduler_json_materialization_unsupported"
    assert fields["scheduler_failure_evidence"][0]["context"]["unsupported_scheduler_value"] is True
    assert replay_tokens
    assert any("scheduler_json_materialization_unsupported" in token for token in replay_tokens)


def test_stage1560_replay_evidence_materializes_raw_hostile_scheduler_values() -> None:
    _reset_hostile_scalar()

    replay_tokens = replay_result_evidence({"scheduler_failure_evidence": [HostileScalar()]})

    assert replay_tokens
    assert any("scheduler_json_materialization_unsupported" in token for token in replay_tokens)
    assert HostileScalar.str_calls == 0
    assert HostileScalar.repr_calls == 0
    assert HostileScalar.bool_calls == 0
    assert HostileScalar.eq_calls == 0


def test_stage1560_replay_result_identity_does_not_call_scalar_hooks() -> None:
    _reset_hostile_scalar()

    job_identity = queue_replay_result_job_identity({
        "job_id": HostileScalar(),
        "file": "sample.bin",
    })

    assert job_identity
    assert HostileScalar.str_calls == 0
    assert HostileScalar.repr_calls == 0
    assert HostileScalar.bool_calls == 0
    assert HostileScalar.eq_calls == 0


def test_stage1560_replay_file_identity_rejects_hostile_path_without_hooks() -> None:
    _reset_hostile_scalar()

    with pytest.raises(RuntimeError, match="missing file path"):
        queue_replay_result_file_identity({"file": HostileScalar()})

    assert HostileScalar.str_calls == 0
    assert HostileScalar.repr_calls == 0
    assert HostileScalar.bool_calls == 0
    assert HostileScalar.eq_calls == 0


def test_stage1560_replay_sequence_rejects_hostile_items_without_hooks() -> None:
    _reset_hostile_scalar()

    with pytest.raises(RuntimeError, match="sequence is malformed"):
        canonical_replay_sequence([HostileScalar()])

    assert HostileScalar.str_calls == 0
    assert HostileScalar.repr_calls == 0
    assert HostileScalar.bool_calls == 0
    assert HostileScalar.eq_calls == 0


def test_stage1560_replay_record_projection_rejects_hostile_tags_without_hooks() -> None:
    _reset_hostile_scalar()

    with pytest.raises(RuntimeError, match="sequence is malformed"):
        QueueReplayComparisonRecord.from_result({
            "job_id": "job-1",
            "file": "sample.bin",
            "verdict": "clean",
            "tags": HostileScalar(),
        })

    assert HostileScalar.str_calls == 0
    assert HostileScalar.repr_calls == 0
    assert HostileScalar.bool_calls == 0
    assert HostileScalar.eq_calls == 0


def test_stage1560_final_json_root_status_scalar_path_does_not_call_hooks() -> None:
    _reset_hostile_scalar()

    section = build_final_json_scheduler_section({
        "scheduler_status": HostileScalar(),
        "degraded": HostileScalar(),
        "queue_failed": HostileScalar(),
        "suppressed_failures": HostileScalar(),
    })

    assert section is not None
    assert section["scheduler_status"] == "fatal"
    assert any(
        item["error_category"] in {
            "scheduler_status_unsupported",
            "queue_failed_unsupported",
            "suppressed_failures_unsupported",
        }
        for item in section["evidence"]
    )
    assert HostileScalar.str_calls == 0
    assert HostileScalar.repr_calls == 0
    assert HostileScalar.bool_calls == 0
    assert HostileScalar.eq_calls == 0


def test_stage1560_checkpoint_reference_status_does_not_call_scalar_hooks() -> None:
    _reset_hostile_scalar()

    section = build_final_json_scheduler_section({"checkpoint_path": HostileScalar()})

    assert section is not None
    assert section["scheduler_status"] == "fatal"
    assert section["evidence"][0]["error_category"] == "scheduler_checkpoint_reference_unsupported"
    assert section["checkpoint"]["unsupported_checkpoint_references"]["checkpoint_path"]["unsupported_scheduler_value"] is True
    assert HostileScalar.str_calls == 0
    assert HostileScalar.repr_calls == 0
    assert HostileScalar.bool_calls == 0
    assert HostileScalar.eq_calls == 0


def test_stage1560_passive_scheduler_result_projection_does_not_call_scalar_hooks() -> None:
    _reset_hostile_scalar()

    records = failure_records_from_scheduler_result_status({
        "scheduler_result": {
            "status": "fatal",
            "error_category": HostileScalar(),
            "queue_id": HostileScalar(),
        }
    })

    assert records
    assert any(record.error_category == "scheduler_result_fatal" for record in records)
    assert HostileScalar.str_calls == 0
    assert HostileScalar.repr_calls == 0
    assert HostileScalar.bool_calls == 0
    assert HostileScalar.eq_calls == 0


def test_stage1560_passive_contract_status_projection_does_not_call_scalar_hooks() -> None:
    _reset_hostile_scalar()

    records = failure_records_from_scheduler_contract_status({
        "timeout_result": {
            "status": "failed",
            "timed_out": True,
            "error_category": HostileScalar(),
            "queue_id": HostileScalar(),
        }
    })

    assert records
    assert any(record.error_category == "timeout_result_timed_out" for record in records)
    assert HostileScalar.str_calls == 0
    assert HostileScalar.repr_calls == 0
    assert HostileScalar.bool_calls == 0
    assert HostileScalar.eq_calls == 0


def test_stage1560_queue_status_projection_does_not_call_scalar_hooks() -> None:
    _reset_hostile_scalar()

    records = failure_records_from_queue_status({
        "queue_integrity_result": {
            "status": "failed",
            "error_category": HostileScalar(),
            "queue_id": HostileScalar(),
        }
    })

    assert records
    assert HostileScalar.str_calls == 0
    assert HostileScalar.repr_calls == 0
    assert HostileScalar.bool_calls == 0
    assert HostileScalar.eq_calls == 0


def test_stage1560_trace_status_projection_does_not_call_scalar_hooks() -> None:
    _reset_hostile_scalar()

    records = failure_records_from_trace_status({
        "trace_status": {
            "status": "failed",
            "error_category": HostileScalar(),
            "queue_id": HostileScalar(),
        }
    })

    assert records
    assert HostileScalar.str_calls == 0
    assert HostileScalar.repr_calls == 0
    assert HostileScalar.bool_calls == 0
    assert HostileScalar.eq_calls == 0


def test_stage1560_passive_status_backstop_does_not_call_scalar_hooks() -> None:
    _reset_hostile_scalar()

    section = build_final_json_scheduler_section({
        "scheduler_custom_status": {
            "status": "failed",
            "error_category": HostileScalar(),
            "queue_id": HostileScalar(),
        }
    })

    assert section is not None
    assert HostileScalar.str_calls == 0
    assert HostileScalar.repr_calls == 0
    assert HostileScalar.bool_calls == 0
    assert HostileScalar.eq_calls == 0


def test_stage1560_replay_status_projection_does_not_call_scalar_hooks() -> None:
    _reset_hostile_scalar()

    record = failure_record_from_replay_status(
        {"queue_id": HostileScalar()},
        {"matched": False, "error_category": HostileScalar()},
    )

    assert record is not None
    assert HostileScalar.str_calls == 0
    assert HostileScalar.repr_calls == 0
    assert HostileScalar.bool_calls == 0
    assert HostileScalar.eq_calls == 0


def test_stage1560_existing_scheduler_section_projection_does_not_call_scalar_hooks() -> None:
    _reset_hostile_scalar()

    record = failure_record_from_existing_scheduler_section(
        {"queue_id": HostileScalar()},
        {"scheduler_status": "fatal", "error_category": HostileScalar()},
    )

    assert record is not None
    assert HostileScalar.str_calls == 0
    assert HostileScalar.repr_calls == 0
    assert HostileScalar.bool_calls == 0
    assert HostileScalar.eq_calls == 0


def test_stage1560_failure_projection_does_not_call_scalar_hooks() -> None:
    _reset_hostile_scalar()

    record = failure_record_from_scheduler_result({
        "queue_failure": True,
        "scheduler_failure_reason": HostileScalar(),
        "queue_id": HostileScalar(),
    })

    assert record is not None
    assert HostileScalar.str_calls == 0
    assert HostileScalar.repr_calls == 0
    assert HostileScalar.bool_calls == 0
    assert HostileScalar.eq_calls == 0


def test_stage1560_explicit_evidence_mapping_does_not_call_scalar_hooks() -> None:
    _reset_hostile_scalar()

    records = collect_scheduler_evidence_values_from_mapping(
        {
            "queue_evidence": {
                "stage": "queue",
                "queue_failure": True,
                "error_category": HostileScalar(),
                "queue_id": HostileScalar(),
            }
        },
        {},
    )

    assert records
    assert HostileScalar.str_calls == 0
    assert HostileScalar.repr_calls == 0
    assert HostileScalar.bool_calls == 0
    assert HostileScalar.eq_calls == 0


def test_stage1560_compact_error_projection_does_not_call_scalar_hooks() -> None:
    _reset_hostile_scalar()

    section = build_final_json_compact_error_section(
        {"input_file_path": HostileScalar(), "queue_id": HostileScalar()},
        error_type=HostileScalar(),
        message=HostileScalar(),
    )

    assert section["scheduler_status"] == "degraded"
    assert section["evidence"][0]["message"] == "compact_record_error"
    assert section["evidence"][0]["path"] == ""
    assert HostileScalar.str_calls == 0
    assert HostileScalar.repr_calls == 0
    assert HostileScalar.bool_calls == 0
    assert HostileScalar.eq_calls == 0



def test_stage1827_compact_error_safe_text_arg_does_not_reintroduce_fallback_keyword_routes() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "scheduler"
        / "evidence"
        / "final_json_compact_error_projection.py"
    ).read_text(encoding="utf-8")

    assert '_safe_text_arg(error_type, fallback="compact_record_error")' not in source
    assert '_safe_text_arg(message, fallback=error_name)' not in source
    assert 'def _safe_text_arg(value: Any, *, fallback: str = "")' not in source
    assert "return fallback" not in source

def test_stage1828_checkpoint_projection_default_text_does_not_call_scalar_hooks() -> None:
    _reset_hostile_scalar()

    record = failure_record_from_checkpoint_status(
        {"queue_id": HostileScalar(), "input_file_path": HostileScalar()},
        {
            "failed": True,
            "error_category": HostileScalar(),
            "stage": HostileScalar(),
            "error_source": HostileScalar(),
            "message": HostileScalar(),
            "checkpoint_path": HostileScalar(),
        },
    )

    assert record is not None
    assert record.error_category == "checkpoint_write_failed"
    assert record.stage == "checkpoint_writer"
    assert record.error_source == "scheduler.evidence.checkpoint_writer"
    assert record.message == "checkpoint_write_failed"
    assert record.queue_id == ""
    assert record.path == ""
    assert HostileScalar.str_calls == 0
    assert HostileScalar.repr_calls == 0
    assert HostileScalar.bool_calls == 0
    assert HostileScalar.eq_calls == 0


def test_stage1828_checkpoint_projection_has_no_first_exact_text_fallback_keyword_routes() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "scheduler"
        / "evidence"
        / "final_json_checkpoint_projection.py"
    ).read_text(encoding="utf-8")

    assert 'first_exact_text(checkpoint_status, "error_category", fallback=' not in source
    assert 'first_exact_text(checkpoint_status, "stage", fallback=' not in source
    assert 'first_exact_text(checkpoint_status, "error_source", fallback=' not in source
    assert 'first_exact_text(checkpoint_status, "message", fallback=' not in source



def test_stage1828_contract_projection_default_text_and_error_source_literals() -> None:
    records = failure_records_from_scheduler_contract_status(
        {"queue_id": "queue-1", "job_id": "job-1"},
        {
            "retry_result": {
                "exhausted": True,
                "fatal": True,
            }
        },
    )

    synthetic = [record for record in records if record.error_source == "scheduler.evidence.retry_result"]
    assert synthetic
    assert synthetic[0].stage == "retry_exhaustion"
    assert synthetic[0].error_category == "retry_exhausted"
    assert synthetic[0].message == "retry_exhausted"


def test_stage1828_contract_projection_has_no_first_exact_text_fallback_keyword_or_dynamic_sources() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "scheduler"
        / "evidence"
        / "final_json_contract_projection.py"
    ).read_text(encoding="utf-8")

    assert "first_exact_text(" in source
    assert "first_exact_text(status, \"stage\",\n        fallback=" not in source
    assert "first_exact_text(status, \"error_category\", \"reason\", \"error\", fallback=" not in source
    assert "first_exact_text(status, \"error_source\", fallback=" not in source
    assert 'f"scheduler.evidence.{field}"' not in source
    assert "def _default_category(field: str, status: Mapping[str, Any], fallback: str)" not in source
    assert "return fallback" not in source

def test_stage1829_evidence_mapping_uses_default_stage_without_fallback_routes() -> None:
    records = collect_scheduler_evidence_values_from_mapping(
        {
            "timeout_evidence": {
                "final_json_must_record": True,
                "timeout_failure": True,
            }
        },
        {"queue_id": "queue-1", "job_id": "job-1"},
    )

    assert len(records) == 1
    assert records[0].stage == "timeout_evidence"
    assert records[0].state == "failure"
    assert records[0].error_category == "timeout_evidence"
    assert records[0].error_source == "scheduler.final_json_projection"
    assert records[0].message == "timeout_evidence"
    assert records[0].queue_id == "queue-1"
    assert records[0].job_id == "job-1"


def test_stage1829_evidence_mapping_source_removes_fallback_prefix_and_stage_routes() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "scheduler"
        / "evidence"
        / "final_json_evidence_mapping.py"
    ).read_text(encoding="utf-8")

    assert "fallback_prefix" not in source
    assert "fallback_stage" not in source
    assert "fallback=fallback_stage" not in source
    assert 'first_exact_text(value, "stage", fallback=' not in source
    assert 'first_exact_text(value, "state", fallback=' not in source
    assert 'first_exact_text(value, "error_source", fallback=' not in source
    assert 'first_exact_text(value, "message", fallback=' not in source


def test_stage1829_exact_mapping_items_uses_dict_descriptor_for_plain_dict() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "scheduler"
        / "evidence"
        / "final_json_exact_fields.py"
    ).read_text(encoding="utf-8")

    assert "return source.items()" not in source
    assert "return dict.items(source)" in source
    assert "def first_exact_text(source: Mapping[str, Any] | None, *keys: str, fallback:" not in source
    assert "return fallback" not in source
    assert tuple(exact_mapping_items({"stage": "scheduler"})) == (("stage", "scheduler"),)
    assert first_exact_text({}, "stage", default_text="scheduler") == "scheduler"

def test_stage1830_passive_scalar_categories_use_exact_string_joins_without_fstrings() -> None:
    assert scalar_failure_category("suppressed_failures", "2") == "suppressed_failures_failure"
    assert scalar_failure_category("suppressed_failures", "bad") == "suppressed_failures_unsupported"
    assert scalar_failure_category("queue_failed", True) == "queue_failed_failure"
    assert scalar_failure_category("queue_status", object()) == "queue_status_unsupported"


def test_stage1830_passive_status_mapping_uses_exact_default_category_and_source() -> None:
    section = build_final_json_scheduler_section({
        "scheduler_custom_status": {
            "status": "failed",
        }
    })

    assert section is not None
    evidence = section["evidence"][0]
    assert evidence["error_category"] == "scheduler_custom_status_failure"
    assert evidence["error_source"] == "scheduler.evidence.scheduler_custom_status"
    assert evidence["message"] == "scheduler_custom_status_failure"


def test_stage1830_passive_scalar_and_status_sources_have_no_dynamic_fstrings_or_fallback_count() -> None:
    root = Path(__file__).resolve().parents[1] / "scheduler" / "evidence"
    scalar_source = (root / "final_json_passive_scalar.py").read_text(encoding="utf-8")
    status_source = (root / "final_json_passive_status_projection.py").read_text(encoding="utf-8")

    assert 'f"{key}_unsupported"' not in scalar_source
    assert 'f"{key}_failure"' not in scalar_source
    assert "fallback=0" not in scalar_source
    assert 'default_text=f"{field}_failure"' not in status_source
    assert 'f"scheduler.evidence.{field}"' not in status_source

def test_stage1831_queue_status_projection_uses_exact_default_error_source() -> None:
    records = failure_records_from_queue_status({
        "queue_integrity_result": {
            "status": "failed",
        }
    })

    assert records
    assert records[0].error_source == "scheduler.evidence.queue_integrity_result"


def test_stage1831_queue_status_projection_source_has_no_dynamic_error_source_fstring() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "scheduler"
        / "evidence"
        / "final_json_queue_projection.py"
    ).read_text(encoding="utf-8")

    assert 'f"scheduler.evidence.{field}"' not in source
    assert "default_text=_queue_error_source(field)" in source
    assert 'return str.__add__("scheduler.evidence.", field)' in source

def test_stage1832_scheduler_result_projection_uses_exact_default_categories() -> None:
    root_records = failure_records_from_scheduler_result_status({"scheduler_status": "failed"})
    result_records = failure_records_from_scheduler_result_status({"scheduler_result": {"status": "failed"}})

    assert root_records
    assert result_records
    assert root_records[0].error_category == "scheduler_root_status_failed"
    assert result_records[0].error_category == "scheduler_result_failed"


def test_stage1832_scheduler_result_projection_source_has_no_dynamic_status_fstrings() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "scheduler"
        / "evidence"
        / "final_json_scheduler_result_projection.py"
    ).read_text(encoding="utf-8")

    assert "f\"scheduler_root_status_{status_text or 'degraded'}\"" not in source
    assert "f\"{field}_{status_text or 'degraded'}\"" not in source
    assert "default_text=_root_status_category(status_text)" in source
    assert "default_text=_result_status_category(field, status_text)" in source

def test_stage1833_scheduler_status_projection_uses_exact_default_category() -> None:
    record = failure_record_from_existing_scheduler_section({}, {"status": "failed"})

    assert record is not None
    assert record.error_category == "scheduler_section_failed"


def test_stage1833_scheduler_status_projection_source_has_no_dynamic_section_fstring() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "scheduler"
        / "evidence"
        / "final_json_scheduler_status_projection.py"
    ).read_text(encoding="utf-8")

    assert "f\"scheduler_section_{status_text or 'degraded'}\"" not in source
    assert "default_text=_scheduler_section_category(status_text)" in source
    assert 'return str.__add__("scheduler_section_", status_text or "degraded")' in source



def test_stage1834_trace_status_projection_uses_exact_reason_text_join_and_source() -> None:
    records = failure_records_from_trace_status({
        "scheduler_trace_write_result": {
            "status": "degraded",
            "reason": "trace write error",
        }
    })

    assert records
    assert records[0].error_category == "trace write error"
    assert records[0].error_source == "scheduler.evidence.scheduler_trace_write_result"


def test_stage1834_trace_status_projection_source_has_no_dynamic_trace_fstrings() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "scheduler"
        / "evidence"
        / "final_json_trace_projection.py"
    ).read_text(encoding="utf-8")

    assert 'f"{status_text} {reason_text}"' not in source
    assert 'f"scheduler.evidence.{field}"' not in source
    assert "_trace_status_reason_text(status_text, reason_text)" in source
    assert 'return str.__add__(str.__add__(status_text, " "), reason_text)' in source
    assert 'return str.__add__("scheduler.evidence.", field)' in source
