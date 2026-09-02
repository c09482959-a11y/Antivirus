from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scheduler.queue import identity_lock
from Virus_Scan.scheduler.evidence.process_queue_monitor_progress_support import (
    MonitorProgressIntDecision,
    monitor_progress_int,
    monitor_progress_int_decision,
)
from Virus_Scan.scheduler.queue.identity_lock import (
    IdentityLockAcquireDecision,
    IdentityLockReleaseDecision,
    acquire_identity_lock_decision,
    release_identity_lock_decision,
)


def _function_returns(source_path: str, function_name: str) -> list[str]:
    tree = ast.parse(Path(source_path).read_text())
    function = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == function_name
    )
    return [ast.unparse(node.value) for node in ast.walk(function) if isinstance(node, ast.Return)]


def test_stage2113_monitor_progress_int_replays_parse_decisions() -> None:
    assert monitor_progress_int_decision(" 7 ", "bad") == MonitorProgressIntDecision(
        value=7,
        accepted=True,
        reason="",
    )
    assert monitor_progress_int_decision("-5", "bad") == MonitorProgressIntDecision(
        value=0,
        accepted=True,
        reason="",
    )
    assert monitor_progress_int_decision("", "bad") == MonitorProgressIntDecision(
        value=0,
        accepted=False,
        reason="bad",
    )
    assert monitor_progress_int_decision(object(), "bad") == MonitorProgressIntDecision(
        value=0,
        accepted=False,
        reason="bad",
    )


def test_stage2113_monitor_progress_int_public_raise_contract_preserved() -> None:
    assert monitor_progress_int(b"9", "bad") == 9
    try:
        monitor_progress_int(b"nan", "bad")
    except ValueError as exc:
        assert str(exc) == "bad"
    else:  # pragma: no cover - contract guard
        raise AssertionError("invalid progress int did not raise")


def test_stage2113_monitor_progress_source_removed_hidden_int_sentinels() -> None:
    returns = _function_returns(
        "Virus_Scan/scheduler/evidence/process_queue_monitor_progress_support.py",
        "_exact_int_text_decision",
    )
    assert "None" not in returns
    assert _function_returns(
        "Virus_Scan/scheduler/evidence/process_queue_monitor_progress_support.py",
        "_clamp_zero",
    ) == ["max(value, 0)"]


def test_stage2113_identity_lock_acquire_decision_preserves_public_contract(tmp_path) -> None:
    rejected = acquire_identity_lock_decision(tmp_path, "invalid:stage2113")
    assert rejected == IdentityLockAcquireDecision(
        acquired=False,
        lock_path=None,
        reason="process_queue_identity_lock_identity_rejected",
    )

    acquired = acquire_identity_lock_decision(tmp_path, "file:stage2113")
    assert acquired.acquired is True
    assert acquired.reason == "process_queue_identity_lock_acquired"
    assert acquired.lock_path is not None
    acquired_bytes = acquired.lock_path.read_bytes()
    competing = acquire_identity_lock_decision(tmp_path, "file:stage2113")
    assert competing.reason == (
        "process_queue_identity_lock_already_locked"
    )
    assert competing.lock_path is None
    assert acquired.lock_path.read_bytes() == acquired_bytes
    assert release_identity_lock_decision(acquired.lock_path).released is True


def test_stage2113_identity_lock_release_decision_preserves_public_contract(tmp_path) -> None:
    lock_path = tmp_path / "stage2113.lock"
    lock_path.write_text("lock", encoding="utf-8")
    assert release_identity_lock_decision(lock_path) == IdentityLockReleaseDecision(
        released=True,
        reason="process_queue_identity_lock_released",
    )
    assert release_identity_lock_decision(None) == IdentityLockReleaseDecision(
        released=True,
        reason="process_queue_identity_lock_release_empty",
    )

    records: list[tuple[str, str]] = []
    rejected = release_identity_lock_decision(
        tmp_path / "missing.lock",
        safe_unlink=lambda _path, log_context: False,
        report_issue=lambda where, exc, **_kwargs: records.append((where, type(exc).__name__)),
    )
    assert rejected == IdentityLockReleaseDecision(
        released=False,
        reason="process_queue_identity_lock_release_unsuccessful",
    )
    assert release_identity_lock_decision(
        tmp_path / "missing.lock",
        safe_unlink=lambda _path, log_context: False,
        report_issue=lambda _where, _exc, **_kwargs: None,
    ).released is False
    assert records == [("process_queue_identity_lock_release_unsuccessful", "RuntimeError")]


def test_stage2113_identity_lock_scalar_compatibility_facades_are_absent() -> None:
    assert not hasattr(identity_lock, "acquire_identity_lock")
    assert not hasattr(identity_lock, "release_identity_lock")
    assert "acquire_identity_lock" not in identity_lock.__all__
    assert "release_identity_lock" not in identity_lock.__all__
