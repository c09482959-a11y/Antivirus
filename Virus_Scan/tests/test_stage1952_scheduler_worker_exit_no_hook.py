from __future__ import annotations

from Virus_Scan.scheduler.workers.inmemory_worker_exit import (
    InMemoryWorkerExitEvidence,
    reconcile_inmemory_worker_exit,
    worker_exit_pid_from_message,
)


class HostileScalar:
    def __bool__(self):
        raise AssertionError("bool hook executed")

    def __int__(self):
        raise AssertionError("int hook executed")

    def __index__(self):
        raise AssertionError("index hook executed")

    def __repr__(self):
        raise AssertionError("repr hook executed")

    def __str__(self):
        raise AssertionError("str hook executed")


class HostileMessage:
    def __len__(self):
        raise AssertionError("len hook executed")

    def __iter__(self):
        raise AssertionError("iter hook executed")

    def __getitem__(self, _index):
        raise AssertionError("getitem hook executed")


class HostileMapping:
    def __bool__(self):
        raise AssertionError("bool hook executed")

    def items(self):
        raise AssertionError("items hook executed")

    def get(self, _key, _default=None):
        raise AssertionError("get hook executed")


class HostileTerminal:
    def __contains__(self, _item):
        raise AssertionError("contains hook executed")

    def __iter__(self):
        raise AssertionError("iter hook executed")


def test_stage1952_worker_exit_rejects_unknown_message_without_hooks() -> None:
    assert worker_exit_pid_from_message(HostileMessage()) == 0


def test_stage1952_worker_exit_evidence_freezes_exact_sequences_without_numeric_hooks() -> None:
    evidence = InMemoryWorkerExitEvidence(
        worker_pid=HostileScalar(),
        active_jobs=(1, "2", HostileScalar()),
        retried_jobs=["3", HostileScalar()],
        ignored_jobs=(HostileScalar(), 4),
    )
    assert evidence.worker_pid == 0
    assert evidence.active_jobs == (1, 2)
    assert evidence.retried_jobs == (3,)
    assert evidence.ignored_jobs == (4,)
    assert evidence.had_active_work is True


def test_stage1952_reconcile_worker_exit_rejects_hostile_boundaries_without_hooks() -> None:
    called: list[int] = []

    try:
        reconcile_inmemory_worker_exit(
            message=("worker_exit", None, None, "9"),
            active=HostileMapping(),
            terminal=HostileTerminal(),
            retry_or_fail=lambda job_id, _reason, *, pid: called.append(job_id) or True,
        )
    except ValueError as exc:
        assert str(exc) == "worker_exit_active_mapping_rejected"
    else:
        raise AssertionError("unsupported active mapping was not rejected")
    assert called == []


def test_stage1952_reconcile_worker_exit_preserves_exact_dict_behavior() -> None:
    retried: list[tuple[int, int]] = []
    evidence = reconcile_inmemory_worker_exit(
        message=("worker_exit", None, None, "9"),
        active={1: {"pid": "9"}, "2": {"pid": 8}, 3: {"pid": 9}},
        terminal={3},
        retry_or_fail=lambda job_id, _reason, *, pid: retried.append((job_id, pid)) or True,
    )

    assert retried == [(1, 9)]
    assert evidence.worker_pid == 9
    assert evidence.active_jobs == (1,)
    assert evidence.retried_jobs == (1,)
    assert evidence.ignored_jobs == ()
