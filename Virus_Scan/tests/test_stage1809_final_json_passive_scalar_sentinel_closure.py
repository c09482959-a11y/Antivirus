from __future__ import annotations

from Virus_Scan.scheduler.evidence.final_json_passive_scalar import scalar_failure_category


class HostileSuppressedFailures:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0
    int_calls = 0

    @classmethod
    def reset(cls) -> None:
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.bool_calls = 0
        cls.iter_calls = 0
        cls.float_calls = 0
        cls.int_calls = 0

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("must not stringify suppressed failures")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("must not repr suppressed failures")

    def __format__(self, spec):
        type(self).format_calls += 1
        raise RuntimeError("must not format suppressed failures")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("must not bool suppressed failures")

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("must not iterate suppressed failures")

    def __float__(self):
        type(self).float_calls += 1
        raise RuntimeError("must not float suppressed failures")

    def __int__(self):
        type(self).int_calls += 1
        raise RuntimeError("must not int suppressed failures")


def test_stage1809_suppressed_failures_invalid_text_is_unsupported_not_clean() -> None:
    assert scalar_failure_category("suppressed_failures", "many") == "suppressed_failures_unsupported"


def test_stage1809_suppressed_failures_preserves_exact_primitives() -> None:
    assert scalar_failure_category("suppressed_failures", 0) == ""
    assert scalar_failure_category("suppressed_failures", "0") == ""
    assert scalar_failure_category("suppressed_failures", 2) == "suppressed_failures_failure"
    assert scalar_failure_category("suppressed_failures", "3") == "suppressed_failures_failure"


def test_stage1809_suppressed_failures_rejects_hostile_value_without_hooks() -> None:
    HostileSuppressedFailures.reset()

    result = scalar_failure_category("suppressed_failures", HostileSuppressedFailures())

    assert result == "suppressed_failures_unsupported"
    assert HostileSuppressedFailures.str_calls == 0
    assert HostileSuppressedFailures.repr_calls == 0
    assert HostileSuppressedFailures.format_calls == 0
    assert HostileSuppressedFailures.bool_calls == 0
    assert HostileSuppressedFailures.iter_calls == 0
    assert HostileSuppressedFailures.float_calls == 0
    assert HostileSuppressedFailures.int_calls == 0
