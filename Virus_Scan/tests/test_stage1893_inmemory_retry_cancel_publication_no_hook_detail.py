from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file, read_python_file


import ast
from pathlib import Path

from Virus_Scan.scheduler.queue.inmemory_retry_cancel_publication import publish_cancel_payload


class HostileTextError(RuntimeError):
    touched = 0

    def __str__(self):  # pragma: no cover - proves unsafe exception text use
        type(self).touched += 1
        raise AssertionError("hostile exception __str__ invoked")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile exception __repr__ invoked")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile exception __format__ invoked")


class HostileReason:
    touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile reason __str__ invoked")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile reason __repr__ invoked")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile reason __format__ invoked")


class FailingCancelSlots:
    def __setitem__(self, _key, _value):
        raise HostileTextError("hidden")


def test_stage1893_cancel_publication_failure_detail_uses_no_hook_exception_projection() -> None:
    HostileTextError.touched = 0
    HostileReason.touched = 0

    result = publish_cancel_payload(
        job_id=1,
        reason=HostileReason(),
        generation=2,
        cancel_table=None,
        cancel_generation=FailingCancelSlots(),
        cancel_flags=FailingCancelSlots(),
    )

    assert result.published is False
    assert result.evidence is not None
    record = result.evidence.as_record()
    assert record["reason"] == "<HostileReason unsupported_retry_reason>"
    assert record["detail"] == "cancel_shared_arrays_rejected"
    assert HostileTextError.touched == 0
    assert HostileReason.touched == 0


def test_stage1893_cancel_publication_missing_reason_uses_owned_recovery_text() -> None:
    result = publish_cancel_payload(
        job_id=1,
        reason=None,
        generation=2,
        cancel_table=None,
        cancel_generation=FailingCancelSlots(),
        cancel_flags=FailingCancelSlots(),
    )

    assert result.published is False
    assert result.evidence is not None
    assert result.evidence.reason == "recovery"


def test_stage1893_cancel_publication_source_has_no_fstrings_or_fallback_keyword() -> None:
    root = Path(__file__).resolve().parents[2]
    source_path = root / "Virus_Scan" / "scheduler" / "queue" / "inmemory_retry_cancel_publication.py"
    source = read_python_file(source_path)
    tree = parse_python_file(source_path)
    assert [node.lineno for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)] == []
    assert "fallback=" not in source
