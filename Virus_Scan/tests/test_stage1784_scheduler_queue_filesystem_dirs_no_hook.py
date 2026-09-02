"""Stage1784 scheduler queue filesystem directory/path no-hook regressions."""
from __future__ import annotations

import os

import pytest

from Virus_Scan.scheduler.runtime.queue_filesystem_common import path_key
from Virus_Scan.scheduler.runtime.queue_filesystem_dirs import (
    queue_claim_meta_path,
    queue_failure_diagnostics_dir,
    queue_file_results_dir,
    queue_identity_index_cache_key,
    queue_job_dirs,
    queue_retire_dir,
)


class HostileValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0
    int_calls = 0
    fspath_calls = 0

    @classmethod
    def reset(cls) -> None:
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.bool_calls = 0
        cls.iter_calls = 0
        cls.float_calls = 0
        cls.int_calls = 0
        cls.fspath_calls = 0

    @classmethod
    def counters(cls) -> dict[str, int]:
        return {
            "str": cls.str_calls,
            "repr": cls.repr_calls,
            "format": cls.format_calls,
            "bool": cls.bool_calls,
            "iter": cls.iter_calls,
            "float": cls.float_calls,
            "int": cls.int_calls,
            "fspath": cls.fspath_calls,
        }

    def __str__(self):  # pragma: no cover - execution is failure
        type(self).str_calls += 1
        raise AssertionError("hostile __str__ executed")

    def __repr__(self):  # pragma: no cover
        type(self).repr_calls += 1
        raise AssertionError("hostile __repr__ executed")

    def __format__(self, _spec):  # pragma: no cover
        type(self).format_calls += 1
        raise AssertionError("hostile __format__ executed")

    def __bool__(self):  # pragma: no cover
        type(self).bool_calls += 1
        raise AssertionError("hostile __bool__ executed")

    def __iter__(self):  # pragma: no cover
        type(self).iter_calls += 1
        raise AssertionError("hostile __iter__ executed")

    def __float__(self):  # pragma: no cover
        type(self).float_calls += 1
        raise AssertionError("hostile __float__ executed")

    def __int__(self):  # pragma: no cover
        type(self).int_calls += 1
        raise AssertionError("hostile __int__ executed")

    def __fspath__(self):  # pragma: no cover
        type(self).fspath_calls += 1
        raise AssertionError("hostile __fspath__ executed")


def assert_no_hostile_hooks() -> None:
    assert HostileValue.counters() == {
        "str": 0,
        "repr": 0,
        "format": 0,
        "bool": 0,
        "iter": 0,
        "float": 0,
        "int": 0,
        "fspath": 0,
    }


def test_stage1784_queue_filesystem_helpers_reject_unsupported_paths_without_hooks() -> None:
    HostileValue.reset()

    for helper in (
        queue_claim_meta_path,
        queue_job_dirs,
        queue_retire_dir,
        queue_file_results_dir,
        queue_failure_diagnostics_dir,
    ):
        with pytest.raises(ValueError, match="scheduler_path_rejected"):
            helper(HostileValue())
    key = path_key(HostileValue())

    assert_no_hostile_hooks()
    assert key.startswith("unsupported_scheduler_queue_path:HostileValue:scheduler_path_rejected")


def test_stage1784_queue_identity_index_cache_key_rejects_unsupported_inputs_without_hooks() -> None:
    HostileValue.reset()

    with pytest.raises(ValueError, match="scheduler_path_rejected"):
        queue_identity_index_cache_key(HostileValue(), HostileValue())

    assert_no_hostile_hooks()


def test_stage1784_queue_identity_index_cache_key_rejects_unsupported_states_without_hooks(tmp_path) -> None:
    HostileValue.reset()

    key = queue_identity_index_cache_key(tmp_path, HostileValue())

    assert_no_hostile_hooks()
    assert key == (os.path.abspath(os.fspath(tmp_path)), ("unsupported_scheduler_queue_state",))


def test_stage1784_queue_filesystem_helpers_preserve_exact_path_primitives(tmp_path) -> None:
    queue_dir = tmp_path / "queue"
    claim = queue_dir / "active" / "job.json"

    pending, active, done, failed = queue_job_dirs(queue_dir)
    assert (pending, active, done, failed) == (
        queue_dir / "pending",
        queue_dir / "active",
        queue_dir / "done",
        queue_dir / "failed",
    )
    assert queue_claim_meta_path(claim) == queue_dir / "active" / "job.json.claim"
    assert queue_failure_diagnostics_dir(queue_dir) == queue_dir / "failure_diagnostics"
    assert queue_retire_dir(queue_dir) == queue_dir / "retire"
    assert queue_file_results_dir(queue_dir) == queue_dir / "file_results"
    assert queue_identity_index_cache_key(queue_dir, ("pending", "active")) == (
        os.path.abspath(os.fspath(queue_dir)),
        ("pending", "active"),
    )
    assert path_key(queue_dir) == os.path.normcase(os.path.abspath(os.fspath(queue_dir)))
