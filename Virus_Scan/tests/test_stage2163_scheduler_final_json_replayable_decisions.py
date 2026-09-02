from __future__ import annotations

import ast
import inspect
import textwrap

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.evidence.final_json_evidence_mapping import (
    SchedulerEvidenceValuesDecision,
    collect_scheduler_evidence_values_from_mapping,
    collect_scheduler_evidence_values_from_mapping_decision,
)
from Virus_Scan.scheduler.evidence.final_json_fields import (
    FinalJsonSchedulerFieldsDecision,
    build_final_json_scheduler_fields,
    build_final_json_scheduler_fields_decision,
)
from Virus_Scan.scheduler.evidence.final_json_status_sources import (
    SchedulerReplayStatusDecision,
    replay_status_from_record,
    replay_status_from_record_decision,
)
from Virus_Scan.scheduler.evidence.records import (
    ExactFlagValueDecision,
    RecordStageFlagDecision,
    _exact_flag_value,
    _exact_flag_value_decision,
    _record_flag_matches_stage,
    _record_flag_matches_stage_decision,
)


class HostileValue:
    touched = 0

    def __getattribute__(self, name: str):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError(f"hostile attribute accessed: {name}")

    def __iter__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("hostile iter invoked")

    def __len__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("hostile len invoked")

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("hostile bool invoked")

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("hostile str invoked")


def _return_expressions(function: object) -> tuple[str, ...]:
    parsed = ast.parse(textwrap.dedent(inspect.getsource(function)))
    return tuple(ast.unparse(node.value) for node in ast.walk(parsed) if isinstance(node, ast.Return))


def test_stage2163_absent_final_json_scheduler_outputs_are_replayable_decisions() -> None:
    evidence = collect_scheduler_evidence_values_from_mapping_decision({}, {})
    assert isinstance(evidence, SchedulerEvidenceValuesDecision)
    assert evidence.values == ()
    assert evidence.reason == "scheduler_evidence_fields_absent"
    assert evidence.accepted is True
    assert collect_scheduler_evidence_values_from_mapping({}, {}) == evidence.values

    fields = build_final_json_scheduler_fields_decision({})
    assert isinstance(fields, FinalJsonSchedulerFieldsDecision)
    assert fields.fields == {}
    assert fields.reason == "scheduler_evidence_absent"
    assert fields.accepted is True
    assert build_final_json_scheduler_fields({}) == fields.fields

    replay = replay_status_from_record_decision({}, None)
    assert isinstance(replay, SchedulerReplayStatusDecision)
    assert replay.status == {}
    assert replay.reason == "replay_status_absent"
    assert replay.accepted is True
    assert replay_status_from_record({}, None) == replay.status


def test_stage2163_unsupported_evidence_mapping_source_is_typed_failure_without_hooks() -> None:
    HostileValue.touched = 0
    value = HostileValue()

    decision = collect_scheduler_evidence_values_from_mapping_decision(value, {})

    assert decision.accepted is False
    assert decision.reason == "unsupported_scheduler_evidence_mapping_source"
    assert decision.source_is_mapping is False
    assert len(decision.values) == 1
    record = decision.values[0]
    assert isinstance(record, SchedulerEvidenceRecord)
    assert record.fatal is True
    assert record.error_category == "scheduler_evidence_source_rejected"
    assert record.context["value_type"] == "HostileValue"
    assert HostileValue.touched == 0


def test_stage2163_scheduler_flag_defaults_are_replayable_decisions() -> None:
    hostile = HostileValue()
    HostileValue.touched = 0

    flag = _exact_flag_value_decision(hostile)
    assert isinstance(flag, ExactFlagValueDecision)
    assert flag.flag is False
    assert flag.reason == "unsupported_flag_value"
    assert flag.value_type == "HostileValue"
    assert _exact_flag_value(hostile) is False

    stage = _record_flag_matches_stage_decision({"other": True}, "worker")
    assert isinstance(stage, RecordStageFlagDecision)
    assert stage.matches is False
    assert stage.reason == "unsupported_stage_fragment"
    assert _record_flag_matches_stage({"other": True}, "worker") is False
    assert HostileValue.touched == 0


def test_stage2163_legacy_projection_wrappers_replay_decision_fields_not_literal_defaults() -> None:
    assert _return_expressions(collect_scheduler_evidence_values_from_mapping) == (
        "collect_scheduler_evidence_values_from_mapping_decision(source, root_record, default_stage_prefix=default_stage_prefix).values",
    )
    assert _return_expressions(build_final_json_scheduler_fields) == (
        "build_final_json_scheduler_fields_decision(record).fields",
    )
    assert _return_expressions(replay_status_from_record) == (
        "replay_status_from_record_decision(record, existing).status",
    )
    assert _return_expressions(_exact_flag_value) == ("_exact_flag_value_decision(value).flag",)
    assert _return_expressions(_record_flag_matches_stage) == (
        "_record_flag_matches_stage_decision(record, stage_fragment).matches",
    )
