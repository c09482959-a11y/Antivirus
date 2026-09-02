from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.tests.support.static_inventory import parse_python_file
from Virus_Scan.scheduler.queue.inmemory_recovery_evidence_journal import (
    InMemoryRecoveryEvidenceJournal,
)


class HostileCancelEvidence:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("str")

    def __repr__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("repr")

    def __format__(self, spec):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("format")

    def __bool__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("bool")

    def __iter__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("iter")


def _journal_tree() -> ast.Module:
    root = Path(__file__).resolve().parents[2]
    source = root / "Virus_Scan" / "scheduler" / "queue" / "inmemory_recovery_evidence_journal.py"
    return parse_python_file(source)


def test_stage1887_cancel_evidence_rejection_field_names_do_not_invoke_hooks() -> None:
    HostileCancelEvidence.reset()
    journal = InMemoryRecoveryEvidenceJournal()

    journal.append_cancel((HostileCancelEvidence(),))
    records = journal.cancel_snapshot()

    assert records[0]["field_name"] == "cancel_only_evidence[0]"
    assert records[0]["reason"] == "recovery_evidence_record_rejected"
    assert HostileCancelEvidence.touched == 0


def test_stage1887_recovery_journal_has_no_fstring_materialization() -> None:
    joined_strings = [node.lineno for node in ast.walk(_journal_tree()) if isinstance(node, ast.JoinedStr)]
    assert joined_strings == []
