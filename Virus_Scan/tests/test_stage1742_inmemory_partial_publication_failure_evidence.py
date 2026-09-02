"""Stage 1742: in-memory partial publication failures stay bounded and explicit."""

from __future__ import annotations

from Virus_Scan.scheduler.evidence.partial_checkpoint_cache import PartialCheckpointCache
from Virus_Scan.scheduler.evidence.inmemory_final_results import (
    InMemoryFinalPublicationRequest,
    publish_inmemory_parent_final_results,
)
from Virus_Scan.scheduler.evidence.inmemory_partial_results import (
    InMemoryPartialPublicationRequest,
    publish_inmemory_partial_results_from_request,
)
from Virus_Scan.scheduler.evidence.scheduler_json_partial import write_partial_scheduler_results


class HostileWriterFailure(RuntimeError):
    touched = 0

    def __str__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("writer exception text hook must not execute")


class HostileLogFailure(RuntimeError):
    pass


def test_stage1742_inmemory_partial_writer_and_logger_failures_do_not_escape_or_stringify(tmp_path) -> None:
    HostileWriterFailure.touched = 0

    def writer(_path, _results, **_kwargs):
        raise HostileWriterFailure("unsafe")

    def log_error(_message):
        raise HostileLogFailure("log unavailable")

    result = publish_inmemory_partial_results_from_request(
        InMemoryPartialPublicationRequest(
            partial_output_path=tmp_path / "partial.json",
            results={"sample.exe": {"status": "done"}},
            partial_output_every=1,
            writer=writer,
            checkpoint_cache=PartialCheckpointCache(),
            log_error=log_error,
            recoverable_exceptions=(HostileWriterFailure, HostileLogFailure),
            terminal_key="sample.exe",
            terminal_record={"status": "done"},
            force=True,
        )
    )

    assert result is False
    assert HostileWriterFailure.touched == 0


def test_stage1742_scheduler_json_partial_writer_and_logger_failures_do_not_escape(tmp_path) -> None:
    HostileWriterFailure.touched = 0

    def write_partial_scan_results(_path, _results, *, make_json_safe):
        raise HostileWriterFailure("unsafe")

    def log_error(_message):
        raise HostileLogFailure("log unavailable")

    record = {"status": "done"}
    last_written = write_partial_scheduler_results(
        partial_output_path=tmp_path / "partial.json",
        results={"sample.exe": record},
        total_files=2,
        partial_output_every=1,
        last_partial_write=7.0,
        now=lambda: 10.0,
        environ_get=lambda _name, _default: "0.25",
        write_partial_scan_results=write_partial_scan_results,
        make_json_safe=lambda value: value,
        log_error=log_error,
        checkpoint_cache=PartialCheckpointCache(),
        force=True,
    )

    assert last_written == 7.0
    assert HostileWriterFailure.touched == 0


def test_stage1742_final_inmemory_publication_reports_forced_write_failure(tmp_path) -> None:
    result = publish_inmemory_parent_final_results(
        InMemoryFinalPublicationRequest(
            partial_output_path=tmp_path / "partial.json",
            results={"sample.exe": {"status": "done"}},
            partial_output_every=1,
            writer=lambda _path, _results, **_kwargs: None,
            checkpoint_cache=PartialCheckpointCache(),
            log_error=lambda _message: None,
            publish_partial_results=lambda _request: False,
            recoverable_exceptions=(RuntimeError, TypeError, ValueError),
        )
    )

    assert result.attempted is True
    assert result.forced is True
    assert result.published is False
    assert result.failure_reason == "partial_publication_not_written"


def test_stage1742_final_inmemory_publication_rejects_non_bool_result_without_hooks(tmp_path) -> None:
    class HostilePublishResult:
        touched = 0

        def __bool__(self):  # pragma: no cover - failure if invoked
            type(self).touched += 1
            raise AssertionError("publish result bool hook must not execute")

        def __str__(self):  # pragma: no cover - failure if invoked
            type(self).touched += 1
            raise AssertionError("publish result str hook must not execute")

    result_value = HostilePublishResult()
    result = publish_inmemory_parent_final_results(
        InMemoryFinalPublicationRequest(
            partial_output_path=tmp_path / "partial.json",
            results={"sample.exe": {"status": "done"}},
            partial_output_every=1,
            writer=lambda _path, _results, **_kwargs: None,
            checkpoint_cache=PartialCheckpointCache(),
            log_error=lambda _message: None,
            publish_partial_results=lambda _request: result_value,
            recoverable_exceptions=(RuntimeError, TypeError, ValueError),
        )
    )

    assert result.published is False
    assert result.failure_reason == "partial_publication_result_rejected"
    assert HostilePublishResult.touched == 0
