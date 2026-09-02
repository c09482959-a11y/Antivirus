"""Stage1564 Phase 2 scheduler contract durable snapshot boundary tests."""
from __future__ import annotations

import gc

from Virus_Scan.scheduler.contracts.queue_snapshot import QueueMergeResult, QueueSnapshot
from Virus_Scan.scheduler.contracts.retry_result import RetryDecision
from Virus_Scan.scheduler.contracts.scheduler_result import SchedulerResult
from Virus_Scan.scheduler.contracts.timeout_result import TimeoutResult
from Virus_Scan.scheduler.contracts.worker_result import WorkerIdentity, WorkerResult, WorkerSnapshot


class HostileValue:
    str_calls = 0
    repr_calls = 0
    bool_calls = 0
    int_calls = 0
    float_calls = 0
    iter_calls = 0

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("str hook called")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("repr hook called")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("bool hook called")

    def __int__(self):
        type(self).int_calls += 1
        raise RuntimeError("int hook called")

    def __float__(self):
        type(self).float_calls += 1
        raise RuntimeError("float hook called")

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("iter hook called")


def _reset() -> None:
    HostileValue.str_calls = 0
    HostileValue.repr_calls = 0
    HostileValue.bool_calls = 0
    HostileValue.int_calls = 0
    HostileValue.float_calls = 0
    HostileValue.iter_calls = 0


def _assert_no_hooks() -> None:
    assert HostileValue.str_calls == 0
    assert HostileValue.repr_calls == 0
    assert HostileValue.bool_calls == 0
    assert HostileValue.int_calls == 0
    assert HostileValue.float_calls == 0
    assert HostileValue.iter_calls == 0


def _contains_object_identity(root, target_id: int, *, max_nodes: int = 4096) -> bool:
    seen: set[int] = set()
    stack = [root]
    while stack and len(seen) < max_nodes:
        current = stack.pop()
        current_id = id(current)
        if current_id == target_id:
            return True
        if current_id in seen:
            continue
        seen.add(current_id)
        try:
            refs = gc.get_referents(current)
        except Exception:  # pragma: no cover - environmental gc failure
            refs = ()
        stack.extend(refs)
    return False


def test_stage1564_queue_snapshot_metadata_and_evidence_do_not_retain_hostile_values() -> None:
    _reset()
    hostile = HostileValue()

    snapshot = QueueSnapshot(metadata={"bad": hostile}, evidence=({"bad": hostile},))
    exported = snapshot.as_dict()

    assert exported["metadata"]["bad"]["unsupported_scheduler_value"] is True
    assert exported["evidence"][0]["bad"]["unsupported_scheduler_value"] is True
    assert not _contains_object_identity(snapshot.metadata, id(hostile))
    assert not _contains_object_identity(snapshot.evidence, id(hostile))
    _assert_no_hooks()


def test_stage1564_queue_merge_result_durable_fields_do_not_retain_hostile_values() -> None:
    _reset()
    hostile = HostileValue()

    result = QueueMergeResult(merged={"bad": hostile}, missing_results=({"bad": hostile},), evidence=({"bad": hostile},))
    exported = result.as_dict()

    assert exported["merged"]["bad"]["unsupported_scheduler_value"] is True
    assert exported["missing_results"][0]["bad"]["unsupported_scheduler_value"] is True
    assert exported["evidence"][0]["bad"]["unsupported_scheduler_value"] is True
    assert not _contains_object_identity(result.merged, id(hostile))
    assert not _contains_object_identity(result.missing_results, id(hostile))
    assert not _contains_object_identity(result.evidence, id(hostile))
    _assert_no_hooks()


def test_stage1564_retry_and_timeout_evidence_do_not_retain_hostile_values() -> None:
    _reset()
    hostile = HostileValue()

    retry = RetryDecision(retry_allowed=False, evidence=({"bad": hostile},))
    timeout = TimeoutResult(evidence=({"bad": hostile},))

    assert retry.as_dict()["evidence"][0]["bad"]["unsupported_scheduler_value"] is True
    assert timeout.as_dict()["evidence"][0]["bad"]["unsupported_scheduler_value"] is True
    assert not _contains_object_identity(retry.evidence, id(hostile))
    assert not _contains_object_identity(timeout.evidence, id(hostile))
    _assert_no_hooks()


def test_stage1564_worker_snapshot_and_result_durable_fields_do_not_retain_hostile_values() -> None:
    _reset()
    hostile = HostileValue()

    snapshot = WorkerSnapshot(workers=({"bad": hostile},), evidence=({"bad": hostile},))
    result = WorkerResult(identity=WorkerIdentity(worker_id="worker-1"), result={"bad": hostile}, failures=({"bad": hostile},))

    assert snapshot.as_dict()["workers"][0]["bad"]["unsupported_scheduler_value"] is True
    assert snapshot.as_dict()["evidence"][0]["bad"]["unsupported_scheduler_value"] is True
    assert result.as_dict()["result"]["bad"]["unsupported_scheduler_value"] is True
    assert result.as_dict()["failures"][0]["bad"]["unsupported_scheduler_value"] is True
    assert not _contains_object_identity(snapshot.workers, id(hostile))
    assert not _contains_object_identity(snapshot.evidence, id(hostile))
    assert not _contains_object_identity(result.result, id(hostile))
    assert not _contains_object_identity(result.failures, id(hostile))
    _assert_no_hooks()


def test_stage1564_scheduler_result_results_and_summary_do_not_retain_hostile_values() -> None:
    _reset()
    hostile = HostileValue()

    result = SchedulerResult(results={"bad": hostile}, summary={"bad": hostile})
    exported = result.as_dict()

    assert exported["results"]["bad"]["unsupported_scheduler_value"] is True
    assert exported["summary"]["bad"]["unsupported_scheduler_value"] is True
    assert not _contains_object_identity(result.results, id(hostile))
    assert not _contains_object_identity(result.summary, id(hostile))
    _assert_no_hooks()
