from Virus_Scan.runtime.structured_failures import clear_failure_records, canonical_failure_snapshot
from Virus_Scan.scheduler.workers.retire_tokens import (
    consume_queue_worker_retire,
    request_queue_worker_retire,
)


class HostileValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0
    int_calls = 0

    @classmethod
    def reset(cls):
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.bool_calls = 0
        cls.iter_calls = 0
        cls.float_calls = 0
        cls.int_calls = 0

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("must not execute")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("must not execute")

    def __format__(self, spec):
        type(self).format_calls += 1
        raise RuntimeError("must not execute")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("must not execute")

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("must not execute")

    def __float__(self):
        type(self).float_calls += 1
        raise RuntimeError("must not execute")

    def __int__(self):
        type(self).int_calls += 1
        raise RuntimeError("must not execute")


def _assert_no_hostile_hooks():
    assert HostileValue.str_calls == 0
    assert HostileValue.repr_calls == 0
    assert HostileValue.format_calls == 0
    assert HostileValue.bool_calls == 0
    assert HostileValue.iter_calls == 0
    assert HostileValue.float_calls == 0
    assert HostileValue.int_calls == 0


def test_stage1789_retire_count_rejects_hostile_without_hooks(tmp_path):
    clear_failure_records()
    HostileValue.reset()
    made = request_queue_worker_retire(tmp_path, HostileValue())
    assert made == 0
    _assert_no_hostile_hooks()
    records = canonical_failure_snapshot()["records"]
    assert any(record["where"] == "queue_worker_retire_count_rejected" for record in records)


def test_stage1789_retire_tokens_preserve_exact_integer_count_and_consume(tmp_path):
    made = request_queue_worker_retire(tmp_path, 2)
    assert made == 2
    assert consume_queue_worker_retire(tmp_path) is True
    assert consume_queue_worker_retire(tmp_path) is True
    assert consume_queue_worker_retire(tmp_path) is False
