from __future__ import annotations

import pytest

from Virus_Scan.scheduler.workers.inmemory_worker_exit import (
    reconcile_inmemory_worker_exit,
    worker_exit_pid_from_message,
)
from Virus_Scan.scheduler.workers.inmemory_worker_exit_decisions import (
    active_worker_items_decision,
    info_pid_decision,
    terminal_job_ids_decision,
    worker_exit_pid_decision_from_message,
)


class HostileMessage:
    def __len__(self):
        raise AssertionError("len hook executed")

    def __iter__(self):
        raise AssertionError("iter hook executed")

    def __getitem__(self, _index):
        raise AssertionError("getitem hook executed")


class HostileMapping:
    def items(self):
        raise AssertionError("items hook executed")

    def get(self, _key, _default=None):
        raise AssertionError("get hook executed")


class HostileTerminal:
    def __iter__(self):
        raise AssertionError("iter hook executed")

    def __contains__(self, _item):
        raise AssertionError("contains hook executed")


def test_stage2106_worker_exit_pid_decision_distinguishes_missing_and_bad_pid() -> None:
    missing = worker_exit_pid_decision_from_message(("worker_exit",))
    assert missing.pid == 0
    assert missing.accepted is False
    assert missing.reason == "worker_exit_message_pid_missing"

    rejected = worker_exit_pid_decision_from_message(("worker_exit", None, None, "bad"))
    assert rejected.pid == 0
    assert rejected.accepted is False
    assert rejected.reason == "worker_exit_message_pid_rejected"

    accepted = worker_exit_pid_decision_from_message(("worker_exit", None, None, "123"))
    assert accepted.pid == 123
    assert accepted.accepted is True
    assert accepted.reason == ""
    assert worker_exit_pid_from_message(("worker_exit", None, None, "123")) == 123


def test_stage2106_worker_exit_mapping_and_terminal_decisions_are_replayable_no_hook() -> None:
    active = active_worker_items_decision(HostileMapping())
    assert active.items == ()
    assert active.accepted is False
    assert active.reason == "worker_exit_active_mapping_rejected"

    terminal = terminal_job_ids_decision(HostileTerminal())
    assert terminal.job_ids == frozenset()
    assert terminal.accepted is False
    assert terminal.reason == "worker_exit_terminal_set_rejected"

    pid = info_pid_decision(HostileMapping())
    assert pid.pid == 0
    assert pid.accepted is False
    assert pid.reason == "worker_exit_owner_mapping_rejected"


def test_stage2106_reconcile_worker_exit_emits_typed_missing_pid_reason() -> None:
    evidence = reconcile_inmemory_worker_exit(
        message=HostileMessage(),
        active={},
        terminal=set(),
        retry_or_fail=lambda *args, **kwargs: True,
    )
    assert evidence.worker_pid == 0
    assert evidence.active_jobs == ()
    assert evidence.retried_jobs == ()
    assert evidence.ignored_jobs == ()
    assert evidence.reason == "worker_exit_message_pid_missing"


def test_stage2106_active_projection_still_rejects_unsupported_mapping() -> None:
    with pytest.raises(ValueError, match="worker_exit_active_mapping_rejected"):
        reconcile_inmemory_worker_exit(
            message=("worker_exit", None, None, "9"),
            active=HostileMapping(),
            terminal=set(),
            retry_or_fail=lambda *args, **kwargs: True,
        )
