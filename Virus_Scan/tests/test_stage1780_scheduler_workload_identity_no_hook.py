from Virus_Scan.scheduler.queue.workload_identity import _sniff_workload_identity, workload_from_identity_outcome


class HostilePathValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    fspath_calls = 0

    @classmethod
    def reset(cls):
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.bool_calls = 0
        cls.iter_calls = 0
        cls.fspath_calls = 0

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("must not execute __str__")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("must not execute __repr__")

    def __format__(self, spec):
        type(self).format_calls += 1
        raise RuntimeError("must not execute __format__")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("must not execute __bool__")

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("must not execute __iter__")

    def __fspath__(self):
        type(self).fspath_calls += 1
        raise RuntimeError("must not execute __fspath__")


def _assert_no_hostile_path_hooks():
    assert HostilePathValue.str_calls == 0
    assert HostilePathValue.repr_calls == 0
    assert HostilePathValue.format_calls == 0
    assert HostilePathValue.bool_calls == 0
    assert HostilePathValue.iter_calls == 0
    assert HostilePathValue.fspath_calls == 0


def test_stage1780_sniff_workload_identity_rejects_hostile_path_before_hooks():
    HostilePathValue.reset()
    hostile = HostilePathValue()

    identity = _sniff_workload_identity(hostile)

    _assert_no_hostile_path_hooks()
    assert identity["magic_stage"] == "unknown"
    assert identity["magic_type"] == "unknown"
    assert identity["confidence"] == 0.0
    assert identity["path_unavailable_reason"] == "scheduler_path_rejected"
    assert workload_from_identity_outcome(identity).accepted is False


def test_stage1780_sniff_workload_identity_preserves_exact_png_path(tmp_path):
    sample = tmp_path / "title.bin"
    sample.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)

    identity = _sniff_workload_identity(sample)

    assert identity["magic_stage"] == "image"
    assert identity["magic_type"] == "png"
    assert identity["confidence"] == 1.0
    assert workload_from_identity_outcome(identity).workload == "image"
