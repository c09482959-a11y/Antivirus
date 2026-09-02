from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.timeout.timeout_budget_workload import (
    configured_timeout_error,
    configured_timeout_error_decision,
    extension,
    infer_workload,
    mb,
    workload_extension_decision,
    workload_size_megabytes_decision,
)


class HostilePath:
    touched = 0

    def __fspath__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("no fspath")

    def __str__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("no str")


class HostileNumber:
    touched = 0

    def __float__(self) -> float:
        type(self).touched += 1
        raise RuntimeError("no float")

    def __int__(self) -> int:
        type(self).touched += 1
        raise RuntimeError("no int")

    def __str__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("no str")


def _reset() -> None:
    HostilePath.touched = 0
    HostileNumber.touched = 0


def test_stage2105_configured_timeout_errors_are_typed_and_replayable() -> None:
    absent = configured_timeout_error_decision(None)
    blank = configured_timeout_error_decision("")
    invalid = configured_timeout_error_decision("abc")
    negative = configured_timeout_error_decision(-1)
    accepted = configured_timeout_error_decision("3.5")

    assert absent.accepted is True
    assert absent.status == "not_configured"
    assert absent.error is None
    assert blank.status == "blank"
    assert blank.error is None
    assert invalid.accepted is False
    assert invalid.error == "configured_timeout_seconds configured_timeout_seconds_rejected"
    assert negative.reason == "configured_timeout_seconds_below_minimum"
    assert configured_timeout_error(-1) == negative.error
    assert accepted.status == "accepted"
    assert accepted.configured_timeout_seconds == 3.5
    assert configured_timeout_error("3.5") is None


def test_stage2105_size_and_extension_decisions_preserve_legacy_projections() -> None:
    size_decision = workload_size_megabytes_decision(2097152)
    rejected_size = workload_size_megabytes_decision("bad")
    extension_decision = workload_extension_decision(Path("payload.RPA"))
    rejected_extension = workload_extension_decision(None)

    assert size_decision.accepted is True
    assert size_decision.megabytes == 2.0
    assert mb(2097152) == 2.0
    assert rejected_size.accepted is False
    assert rejected_size.reason == "timeout_size_rejected"
    assert mb("bad") == 0.0
    assert extension_decision.extension == ".rpa"
    assert extension(Path("payload.RPA")) == ".rpa"
    assert rejected_extension.reason == "scheduler_path_missing"
    assert extension(None) == ""


def test_stage2105_workload_decisions_reject_hostile_values_without_hooks() -> None:
    _reset()
    hostile_path = HostilePath()
    hostile_number = HostileNumber()

    size_decision = workload_size_megabytes_decision(hostile_number)  # type: ignore[arg-type]
    extension_decision = workload_extension_decision(hostile_path)  # type: ignore[arg-type]
    workload = infer_workload(hostile_path, "archive", None, ("tag",))  # type: ignore[arg-type]

    assert size_decision.accepted is False
    assert extension_decision.accepted is False
    assert workload == "archive"
    assert HostilePath.touched == 0
    assert HostileNumber.touched == 0
