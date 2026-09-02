from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.workers.lifecycle_boundary import SchedulerIsolationBoundary, WorkerLifecycleEvent


class HostileScalar:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def _hit(self, _name: str) -> object:
        type(self).touched += 1
        raise AssertionError("caller-owned hook invoked")

    def __bool__(self):  # pragma: no cover - failure proves unsafe truthiness
        return self._hit("__bool__")

    def __float__(self):  # pragma: no cover
        return self._hit("__float__")

    def __format__(self, _spec):  # pragma: no cover
        return self._hit("__format__")

    def __int__(self):  # pragma: no cover
        return self._hit("__int__")

    def __iter__(self):  # pragma: no cover
        return self._hit("__iter__")

    def __repr__(self):  # pragma: no cover
        return self._hit("__repr__")

    def __str__(self):  # pragma: no cover
        return self._hit("__str__")


def test_stage1959_worker_lifecycle_rejects_hostile_scheduler_id_without_default_transition() -> None:
    HostileScalar.reset()
    boundary = SchedulerIsolationBoundary(scheduler_id=HostileScalar())

    result = boundary.transition(WorkerLifecycleEvent("worker", "queue", "new", "queued"))

    assert result["status"] == "rejected"
    assert result["scheduler_id"] == "scheduler"
    assert boundary.state_of("queue") == "new"
    assert any(item["field_name"] == "scheduler_id" for item in result["input_rejections"])
    assert HostileScalar.touched == 0


def test_stage1959_worker_lifecycle_mapping_keys_and_state_lookup_reject_without_hooks() -> None:
    HostileScalar.reset()
    hostile_key = HostileScalar()
    boundary = SchedulerIsolationBoundary(scheduler_id="stage1959")

    result = boundary.transition(
        {
            hostile_key: "ignored",
            "worker_id": "worker",
            "queue_id": "queue",
            "from_state": "new",
            "to_state": "queued",
        }
    )

    assert result["status"] == "rejected"
    assert boundary.state_of("queue") == "new"
    assert any(item["field_name"] == "worker_lifecycle_key_0" for item in result["input_rejections"])

    try:
        boundary.state_of(HostileScalar())  # type: ignore[arg-type]
    except ValueError as exc:
        assert exc.args == ("worker lifecycle queue_id rejected: HostileScalar",)
    else:  # pragma: no cover
        raise AssertionError("hostile queue_id was accepted")
    assert HostileScalar.touched == 0


def test_stage1959_worker_lifecycle_source_has_no_fallback_or_fstring_routes() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "scheduler" / "workers" / "lifecycle_boundary.py").read_text(encoding="utf-8")

    forbidden = (
        "fallback",
        'f"',
        "f'",
        "dict(rejections)",
        "owner=f",
        "RuntimeError(f",
        "ValueError(f",
        "default=",
    )
    for snippet in forbidden:
        assert snippet not in source
