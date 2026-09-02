from dataclasses import fields
from inspect import signature
from pathlib import Path

from Virus_Scan.scheduler.workers.child_result_publication import (
    ChildResultPersistRequest,
    WorkerOutputUpdateRequest,
    persist_child_result,
    update_worker_output,
)
from Virus_Scan.scheduler.internal.output_publication import write_worker_output_payload


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


class HostileWriterResult:
    bool_calls = 0
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    iter_calls = 0

    @classmethod
    def reset(cls):
        cls.bool_calls = 0
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.iter_calls = 0

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("must not execute __bool__")

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("must not execute __str__")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("must not execute __repr__")

    def __format__(self, spec):
        type(self).format_calls += 1
        raise RuntimeError("must not execute __format__")

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("must not execute __iter__")


def _assert_hostile_path_untouched():
    assert HostilePathValue.str_calls == 0
    assert HostilePathValue.repr_calls == 0
    assert HostilePathValue.format_calls == 0
    assert HostilePathValue.bool_calls == 0
    assert HostilePathValue.iter_calls == 0
    assert HostilePathValue.fspath_calls == 0


def _assert_hostile_writer_result_untouched():
    assert HostileWriterResult.bool_calls == 0
    assert HostileWriterResult.str_calls == 0
    assert HostileWriterResult.repr_calls == 0
    assert HostileWriterResult.format_calls == 0
    assert HostileWriterResult.iter_calls == 0


def test_stage1781_worker_output_publication_has_exact_noninjectable_path():
    request_fields = {field.name for field in fields(WorkerOutputUpdateRequest)}
    assert tuple(signature(write_worker_output_payload).parameters) == ("path", "payload")
    assert "write_worker_output" not in request_fields
    assert "output_buffer" not in request_fields


def test_stage1781_worker_output_payload_rejects_hostile_path_before_hooks():
    HostilePathValue.reset()

    assert write_worker_output_payload(HostilePathValue(), {"x": 1}) is False

    _assert_hostile_path_untouched()


def test_stage1781_worker_output_payload_preserves_exact_path_behavior(tmp_path):
    output_path = tmp_path / "worker.json"

    assert write_worker_output_payload(output_path, {"x": 1}) is True
    assert output_path.read_text(encoding="utf-8") == '{"x":1}'


def test_stage1781_persist_child_result_rejects_hostile_status_before_bool(tmp_path):
    HostileWriterResult.reset()
    calls = []

    result = persist_child_result(
        ChildResultPersistRequest(
            queue_dir=tmp_path,
            claim_path=tmp_path / "claim",
            file_path=tmp_path / "file.bin",
            result={"scan_integrity": {}},
            context="child",
            write_result=lambda queue_dir, claim_path, file_path, result: HostileWriterResult(),
            report=lambda where, exc: calls.append((where, type(exc).__name__, exc.args)),
        )
    )

    assert result is False
    _assert_hostile_writer_result_untouched()
    assert calls == [("child.result_persist_result_rejected", "RuntimeError", ("scheduler_worker_publication_status_rejected",))]


def test_stage1781_update_worker_output_records_canonical_writer_rejection(tmp_path):
    calls = []
    child_results = {}
    blocked_parent = tmp_path / "blocked-parent"
    blocked_parent.write_text("not a directory", encoding="utf-8")

    result = update_worker_output(
        WorkerOutputUpdateRequest(
            worker_output_path=str(blocked_parent / "worker.json"),
            file_path=str(tmp_path / "file.bin"),
            result={"scan_integrity": {}},
            child_results=child_results,
            context="aggregate",
            report=lambda where, exc: calls.append((where, type(exc).__name__, exc.args)),
        )
    )

    assert result is False
    assert calls == [
        (
            "aggregate.aggregate_write_rejected",
            "RuntimeError",
            ("aggregate worker output publication rejected",),
        )
    ]
    sentinel = child_results["__scheduler_worker_output_publication_failure__"]
    assert sentinel["worker_output_publication_stage"] == "aggregate_write_rejected"
    assert sentinel["queue_failure"] is True


def test_stage1959_output_publication_source_has_no_fallback_fstring_or_bare_false_returns():
    root = Path(__file__).resolve().parents[1]
    source = (root / "scheduler" / "internal" / "output_publication.py").read_text(encoding="utf-8")

    assert "fallback" not in source
    assert 'f"{safe_context}' not in source
    assert "report_failure(f" not in source
    assert "return False" not in source
    assert "default=False" not in source
