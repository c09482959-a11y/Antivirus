from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.evidence.partial_checkpoint_cache import PartialCheckpointCache
from Virus_Scan.scheduler.evidence.inmemory_partial_results import (
    InMemoryPartialPublicationRequest,
    publish_inmemory_partial_results_from_request,
)
from Virus_Scan.scheduler.evidence.scheduler_json_partial import write_partial_scheduler_results


class HostilePath:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call bool")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not call str")

    def __fspath__(self):
        type(self).touched += 1
        raise RuntimeError("do not call fspath")


class HostileEvery:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call bool")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("do not call int")

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("do not call float")


class HostileResults:
    touched = 0

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("do not call len")


class HostileFloat:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call bool")

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("do not call float")


class HostileForce:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call bool")


def _reset_hostiles() -> None:
    for cls in (HostilePath, HostileEvery, HostileResults, HostileFloat, HostileForce):
        cls.touched = 0


def _scheduler_values(**values: object) -> dict[str, object]:
    defaults: dict[str, object] = {
        "partial_output_path": "safe-output.json",
        "results": {"a": 1},
        "total_files": 10,
        "partial_output_every": 1,
        "last_partial_write": 0.0,
        "now": lambda: 1.0,
        "environ_get": lambda _name, default: default,
        "write_partial_scan_results": lambda _path, _results, **_kwargs: True,
        "make_json_safe": lambda value: value,
        "log_error": lambda _message: None,
        "checkpoint_cache": PartialCheckpointCache(),
    }
    defaults.update(values)
    return defaults


def test_stage1630_inmemory_partial_results_rejects_hostile_inputs_without_hooks() -> None:
    _reset_hostiles()
    log_messages: list[str] = []
    writer_calls: list[tuple[str, object]] = []

    result = publish_inmemory_partial_results_from_request(
        InMemoryPartialPublicationRequest(
            partial_output_path=HostilePath(),
            results={"a": 1},
            partial_output_every=1,
            writer=lambda path, results, **_kwargs: writer_calls.append((path, results)),
            checkpoint_cache=PartialCheckpointCache(),
            log_error=log_messages.append,
            recoverable_exceptions=(RuntimeError, TypeError, ValueError),
            terminal_key="a",
            terminal_record=1,
            force=HostileForce(),
        )
    )

    assert result is False
    assert HostilePath.touched == 0
    assert HostileForce.touched == 0
    assert writer_calls == []
    assert any("partial_output_path" in item and "rejected" in item for item in log_messages)


def test_stage1630_scheduler_json_partial_rejects_hostile_numeric_and_results_without_hooks() -> None:
    _reset_hostiles()
    log_messages: list[str] = []
    writer_calls: list[tuple[str, object]] = []

    result = write_partial_scheduler_results(
        **_scheduler_values(
            results=HostileResults(),
            total_files=HostileEvery(),
            partial_output_every=HostileEvery(),
            last_partial_write=HostileFloat(),
            now=lambda: HostileFloat(),
            environ_get=lambda _name, _default: HostileFloat(),
            write_partial_scan_results=lambda path, results, **_kwargs: writer_calls.append((path, results)) or True,
            log_error=log_messages.append,
            force=HostileForce(),
        )
    )

    assert result == 0.0
    assert HostileResults.touched == 0
    assert HostileEvery.touched == 0
    assert HostileFloat.touched == 0
    assert HostileForce.touched == 0
    assert writer_calls == []
    assert any("results" in item and "rejected" in item for item in log_messages)


def test_stage1630_partial_output_success_paths_preserve_canonical_behavior(tmp_path: Path) -> None:
    _reset_hostiles()
    writes: list[tuple[str, object]] = []
    logs: list[str] = []
    target = tmp_path / "partial.json"
    record = {"classification": "malicious", "score": 92, "tags": ["script"]}
    cache = PartialCheckpointCache()

    assert publish_inmemory_partial_results_from_request(
        InMemoryPartialPublicationRequest(
            partial_output_path=target,
            results={"a": record},
            partial_output_every="1",
            writer=lambda path, results, **_kwargs: writes.append((path, results)) or True,
            checkpoint_cache=cache,
            log_error=logs.append,
            recoverable_exceptions=(RuntimeError, TypeError, ValueError),
            terminal_key="a",
            terminal_record=record,
            force=False,
        )
    ) is True
    assert writes[0][0] == str(target) + ".partial"
    delta_items = tuple(writes[0][1].items)
    assert tuple(key for key, _record in delta_items) == ("a",)
    assert delta_items[0][1]["classification"] == "malicious"
    assert writes[0][1].total_records == 1
    assert cache.pending_records == {}
    assert logs == []

    scheduler_writes: list[tuple[str, object]] = []
    scheduler_cache = PartialCheckpointCache()
    next_write = write_partial_scheduler_results(
        **_scheduler_values(
            partial_output_path=target,
            results={"a": record},
            total_files=10,
            partial_output_every="1",
            last_partial_write=1.0,
            now=lambda: 4.0,
            environ_get=lambda _name, _default: "2.0",
            write_partial_scan_results=lambda path, results, **_kwargs: scheduler_writes.append((path, results)) or True,
            log_error=logs.append,
            checkpoint_cache=scheduler_cache,
            force=False,
        )
    )
    assert next_write == 4.0
    assert scheduler_writes[0][0] == str(target) + ".partial"
    assert tuple(key for key, _record in scheduler_writes[0][1].items) == ("a",)
    assert scheduler_cache.pending_records == {}
    assert logs == []


def test_stage1837_partial_output_support_uses_exact_owned_rejection_routes() -> None:
    _reset_hostiles()
    log_messages: list[str] = []

    result = write_partial_scheduler_results(
        **_scheduler_values(
            results={"a": 1},
            total_files=HostileEvery(),
            partial_output_every=HostileEvery(),
            last_partial_write=HostileFloat(),
            now=lambda: HostileFloat(),
            environ_get=lambda _name, _default: HostileFloat(),
            log_error=log_messages.append,
            force=HostileForce(),
        )
    )

    assert result == 0.0
    assert HostileEvery.touched == 0
    assert HostileFloat.touched == 0
    assert HostileForce.touched == 0
    assert "scheduler_json_partial: last_partial_write rejected without caller hooks: unsafe_last_partial_write" in log_messages
    assert "scheduler_json_partial: partial_output_every rejected without caller hooks: unsafe_partial_output_every" in log_messages


def test_stage1837_partial_output_support_source_has_no_fallback_or_fstring_rejection() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "scheduler"
        / "evidence"
        / "partial_output_support.py"
    ).read_text(encoding="utf-8")

    assert "fallback=" not in source
    assert 'f"{context_text}: {field} rejected without caller hooks: {reason}"' not in source
    assert 'f"unsafe_{field}"' not in source
    assert "scheduler_text(" not in source
    assert "scheduler_int(" not in source
    assert "scheduler_float(" not in source
    exception_block = source[
        source.index("except (OSError, RuntimeError, TypeError, ValueError):"):
        source.index("def _partial_context_text")
    ]
    assert "return False" not in exception_block
    assert 'str.__add__("unsafe_", field)' in source
    assert "_partial_rejection_message(" in source
