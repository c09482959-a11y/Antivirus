from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_context_with_issues, scheduler_text_field
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping


class HostileIssues(Mapping):
    touched: dict[str, int] = {
        "items": 0,
        "keys": 0,
        "iter": 0,
        "len": 0,
        "getitem": 0,
        "str": 0,
        "repr": 0,
    }

    @classmethod
    def reset(cls) -> None:
        for key in cls.touched:
            cls.touched[key] = 0

    def __getitem__(self, key: object) -> object:
        type(self).touched["getitem"] += 1
        raise RuntimeError("getitem must not execute")

    def __iter__(self):
        type(self).touched["iter"] += 1
        raise RuntimeError("iter must not execute")

    def __len__(self) -> int:
        type(self).touched["len"] += 1
        raise RuntimeError("len must not execute")

    def items(self):
        type(self).touched["items"] += 1
        raise RuntimeError("items must not execute")

    def keys(self):
        type(self).touched["keys"] += 1
        raise RuntimeError("keys must not execute")

    def __str__(self) -> str:
        type(self).touched["str"] += 1
        raise RuntimeError("str must not execute")

    def __repr__(self) -> str:
        type(self).touched["repr"] += 1
        raise RuntimeError("repr must not execute")


def _assert_no_hooks() -> None:
    assert HostileIssues.touched == {key: 0 for key in HostileIssues.touched}


class HostileText:
    touched = 0

    def __str__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("text hook must not execute")

    def __repr__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("repr hook must not execute")


def test_stage1748_scheduler_context_issues_rejects_hostile_issue_mapping_without_hooks() -> None:
    HostileIssues.reset()

    merged = scheduler_context_with_issues({"existing": True}, HostileIssues())

    _assert_no_hooks()
    assert merged["existing"] is True
    evidence = merged["context_issues_materialization"]
    assert evidence["unsupported_scheduler_value"] is True
    assert evidence["field_name"] == "context_issues"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_must_record"] is True


def test_stage1748_scheduler_evidence_record_internal_issues_still_hit_production_context_path() -> None:
    HostileText.touched = 0

    record = SchedulerEvidenceRecord(stage=HostileText(), context={"input": "safe"})
    context = materialize_scheduler_mapping(record.context)

    assert HostileText.touched == 0
    assert context["input"] == "safe"
    assert context["stage_materialization"]["scheduler_evidence_field_rejected"] is True
    assert context["stage_materialization"]["field_name"] == "stage"



def test_stage1827_scheduler_evidence_record_text_fields_do_not_reintroduce_fallback_keyword_routes() -> None:
    contracts_root = Path(__file__).resolve().parents[1] / "scheduler" / "contracts"
    evidence_record_source = (contracts_root / "evidence_record.py").read_text(encoding="utf-8")
    support_source = (contracts_root / "evidence_record_support.py").read_text(encoding="utf-8")

    assert "scheduler_text_field(self.stage, field_name=\"stage\", fallback=" not in evidence_record_source
    assert "def scheduler_text_field(value: Any, *, field_name: str, fallback: str)" not in support_source
    assert "return fallback" not in support_source
    assert 'f"{field_name}_materialization"' not in support_source
    assert 'f"context_issue_key_{len(merged)}"' not in support_source


def test_stage1827_scheduler_text_field_uses_explicit_default_text_without_hooks() -> None:
    HostileText.touched = 0

    text, issue = scheduler_text_field(HostileText(), field_name="stage", default_text="scheduler")

    assert text == "scheduler"
    assert issue is not None
    assert issue[0] == "stage_materialization"
    assert issue[1]["scheduler_evidence_field_rejected"] is True
    assert HostileText.touched == 0
