import ast
from pathlib import Path

import pytest

from Virus_Scan.scheduler.queue.inmemory_retry_cancel_publication import (
    publish_cancel_payload,
)
from Virus_Scan.scheduler.queue.inmemory_retry_publication import (
    record_retry_pending_publication_failure,
)
from Virus_Scan.scheduler.queue.inmemory_retry_result_evidence import (
    InMemoryRetryPendingPublicationEvidence,
)
from Virus_Scan.scheduler.queue.retry_callback_evidence import (
    retry_policy_callback_evidence,
)


class _HookBomb:
    def __init__(self):
        self.calls = []

    def _called(self, name):
        self.calls.append(name)
        raise AssertionError(f"hostile hook called: {name}")

    def __int__(self):
        return self._called("__int__")

    def __bool__(self):
        return self._called("__bool__")

    def __str__(self):
        return self._called("__str__")

    def __repr__(self):
        return self._called("__repr__")

    def __format__(self, _spec):
        return self._called("__format__")

    def __iter__(self):
        return self._called("__iter__")

    def __getitem__(self, _key):
        return self._called("__getitem__")

    def __setitem__(self, _key, _value):
        return self._called("__setitem__")

    def items(self):
        return self._called("items")


def _pending_evidence():
    return InMemoryRetryPendingPublicationEvidence(
        job_id=3,
        generation=2,
        reason="worker_timeout",
        file="sample.bin",
        error_category="RuntimeError",
        error_source="test",
        detail="pending publication failed",
    )


def test_stage1786_evidence_constructor_rejects_hostile_numeric_without_hooks():
    hostile = _HookBomb()

    with pytest.raises(ValueError, match="scheduler_retry_job_id_rejected"):
        InMemoryRetryPendingPublicationEvidence(
            job_id=hostile,
            generation=2,
            reason="worker_timeout",
            file="sample.bin",
            error_category="RuntimeError",
            error_source="test",
            detail="pending publication failed",
        )

    assert hostile.calls == []


def test_stage1786_publication_records_malformed_mapping_without_mapping_hooks():
    hostile = _HookBomb()

    record = record_retry_pending_publication_failure(
        record=hostile,
        evidence=_pending_evidence(),
    )

    assert hostile.calls == []
    assert record["scheduler_retry_mapping_rejected"] is True
    assert record["value_type"] == "_HookBomb"
    assert record["retry_pending_publication_failed"] is True
    assert record["history"][-1]["action"] == "retry_pending_publication_failed"


def test_stage1786_publication_records_malformed_history_without_iteration_hooks():
    hostile = _HookBomb()

    record = record_retry_pending_publication_failure(
        record={"history": hostile},
        evidence=_pending_evidence(),
    )

    assert hostile.calls == []
    assert record["history"][0]["action"] == "retry_history_rejected"
    assert record["history"][1]["action"] == "retry_pending_publication_failed"


def test_stage1786_cancel_rejects_hostile_job_id_without_conversion_hooks():
    hostile = _HookBomb()

    result = publish_cancel_payload(
        job_id=hostile,
        reason="worker_timeout",
        generation=2,
        cancel_table={},
        cancel_generation=None,
        cancel_flags=None,
    )

    assert hostile.calls == []
    assert result.published is False
    assert result.evidence is not None
    assert result.evidence.error_category == "cancel_publication_failed"


def test_stage1786_cancel_rejects_hostile_slots_without_mutation_hooks():
    hostile = _HookBomb()

    result = publish_cancel_payload(
        job_id=1,
        reason="worker_timeout",
        generation=2,
        cancel_table=None,
        cancel_generation=hostile,
        cancel_flags=hostile,
    )

    assert hostile.calls == []
    assert result.published is False
    assert result.evidence is not None


def test_stage1786_cancel_writes_valid_owned_list_slots():
    generations = [0, 0]
    flags = [0, 0]

    result = publish_cancel_payload(
        job_id=1,
        reason="worker_timeout",
        generation=2,
        cancel_table=None,
        cancel_generation=generations,
        cancel_flags=flags,
        flags=7,
    )

    assert result.published is True
    assert result.evidence is None
    assert generations == [0, 2]
    assert flags == [0, 7]


def test_stage1786_retry_callback_rejects_hostile_attempt_without_hooks():
    hostile = _HookBomb()

    with pytest.raises(ValueError, match="scheduler_retry_attempt_rejected"):
        retry_policy_callback_evidence(
            path="sample.bin",
            attempt=hostile,
            callback_name="backoff",
            error=RuntimeError("callback failed"),
        )

    assert hostile.calls == []


def test_stage1786_retry_boundary_modules_keep_raw_conversions_closed():
    root = Path(__file__).parents[1] / "scheduler" / "queue"
    targets = (
        "inmemory_retry_cancel_evidence.py",
        "inmemory_retry_cancel_publication.py",
        "inmemory_retry_contract_evidence.py",
        "inmemory_retry_contracts.py",
        "inmemory_retry_lifecycle_evidence.py",
        "inmemory_retry_publication.py",
        "inmemory_retry_result_evidence.py",
        "retry_callback_evidence.py",
        "retry_integrity_evidence.py",
        "retry_publication_evidence.py",
    )

    for name in targets:
        source = (root / name).read_text(encoding="utf-8")
        tree = ast.parse(source)
        raw_calls = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name) and node.func.id in {"int", "bool"}:
                raw_calls.append((node.func.id, node.lineno))
        assert raw_calls == []
        assert "dict(record or {})" not in source
        assert len(source.splitlines()) < 200
