"""Stage 1736: scheduler timeout projection rejects live sequence/numeric subclasses."""

from __future__ import annotations

from Virus_Scan.publication.json_finalization.scheduler_projection import timeout_evidence_projection


class HostileList(list):
    touched = 0

    def __getitem__(self, key):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned list __getitem__ must not execute")

    def __iter__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned list __iter__ must not execute")


class HostileInt(int):
    touched = 0

    def __str__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned int __str__ must not execute")

    def __repr__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned int __repr__ must not execute")


class HostileFloat(float):
    touched = 0

    def __float__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned float __float__ must not execute")

    def __repr__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned float __repr__ must not execute")


class HostileStr(str):
    touched = 0

    def __str__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned str __str__ must not execute")

    def __getitem__(self, key):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned str __getitem__ must not execute")


def reset_hooks() -> None:
    HostileList.touched = 0
    HostileInt.touched = 0
    HostileFloat.touched = 0
    HostileStr.touched = 0


def assert_projection_failure(value) -> None:
    assert isinstance(value, dict)
    assert value["model_signal_projection_failed"] is True
    assert "reason" in value


def test_stage1736_timeout_evidence_rejects_list_subclass_without_slicing_hook() -> None:
    reset_hooks()

    projected = timeout_evidence_projection({"timeout_reason": HostileList(["late"])})

    assert projected is not None
    assert_projection_failure(projected["timeout_reason"])
    assert HostileList.touched == 0


def test_stage1736_timeout_evidence_rejects_scalar_subclasses_with_evidence() -> None:
    reset_hooks()

    projected = timeout_evidence_projection(
        {
            "progress_age": HostileInt(4),
            "heartbeat_age": HostileFloat(0.25),
            "worker_state": HostileStr("running"),
        }
    )

    assert projected is not None
    assert_projection_failure(projected["progress_age"])
    assert_projection_failure(projected["heartbeat_age"])
    assert projected["worker_state"] == "running"
    assert HostileInt.touched == 0
    assert HostileFloat.touched == 0
    assert HostileStr.touched == 0
