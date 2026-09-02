"""Stage2107: in-memory partial result publication uses typed replayable decisions."""

from __future__ import annotations

from Virus_Scan.scheduler.evidence.inmemory_partial_result_decisions import (
    inmemory_partial_publication_decision,
)
from Virus_Scan.scheduler.evidence.partial_checkpoint_cache import PartialCheckpointCache
from Virus_Scan.scheduler.evidence.inmemory_partial_results import (
    InMemoryPartialPublicationRequest,
    publish_inmemory_partial_results_from_request,
)


class _HostileResults:
    touched = 0

    def __len__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("result length hook executed")


class _HostileForce:
    touched = 0

    def __bool__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("force bool hook executed")


def test_stage2107_decision_records_missing_target_without_legacy_false_projection() -> None:
    logs: list[str] = []

    decision = inmemory_partial_publication_decision(
        partial_output_path=None,
        results={"one": 1},
        partial_output_every=1,
        log_error=logs.append,
    )

    assert decision.should_attempt is False
    assert decision.target == ""
    assert decision.reason == "scheduler_path_missing"
    assert decision.result_count == 0


def test_stage2107_decision_records_unsupported_results_without_len_hook(tmp_path) -> None:
    _HostileResults.touched = 0
    logs: list[str] = []

    decision = inmemory_partial_publication_decision(
        partial_output_path=tmp_path / "partial.json",
        results=_HostileResults(),
        partial_output_every=1,
        log_error=logs.append,
    )

    assert decision.should_attempt is False
    assert decision.reason == "partial_results_count_unavailable"
    assert _HostileResults.touched == 0
    assert any("results" in item and "rejected" in item for item in logs)


def test_stage2107_publish_projection_preserves_writer_success_and_failure(tmp_path) -> None:
    writes: list[tuple[str, object]] = []
    logs: list[str] = []

    assert publish_inmemory_partial_results_from_request(
        InMemoryPartialPublicationRequest(
            partial_output_path=tmp_path / "partial.json",
            results={"sample": {"status": "done"}},
            partial_output_every=1,
            writer=lambda path, results, **_kwargs: writes.append((path, results)) or True,
            checkpoint_cache=PartialCheckpointCache(),
            log_error=logs.append,
            recoverable_exceptions=(RuntimeError, TypeError, ValueError),
            terminal_key="sample",
            terminal_record={"status": "done"},
        )
    ) is True
    assert writes[0][0] == str(tmp_path / "partial.json") + ".partial"
    assert tuple(writes[0][1].items)[0][0] == "sample"

    assert publish_inmemory_partial_results_from_request(
        InMemoryPartialPublicationRequest(
            partial_output_path=tmp_path / "partial.json",
            results={"sample": {"status": "done"}},
            partial_output_every=1,
            writer=lambda _path, _results, **_kwargs: (_ for _ in ()).throw(RuntimeError("failed")),
            checkpoint_cache=PartialCheckpointCache(),
            log_error=logs.append,
            recoverable_exceptions=(RuntimeError, TypeError, ValueError),
            terminal_key="sample",
            terminal_record={"status": "done"},
            force=True,
        )
    ) is False
    assert any("partial JSON save failed" in item for item in logs)


def test_stage2107_non_boolean_writer_result_does_not_commit_checkpoint(tmp_path) -> None:
    cache = PartialCheckpointCache()
    request = InMemoryPartialPublicationRequest(
        partial_output_path=tmp_path / "partial.json",
        results={"sample": {"status": "done"}},
        partial_output_every=1,
        writer=lambda _path, _results, **_kwargs: None,
        checkpoint_cache=cache,
        log_error=lambda _message: None,
        recoverable_exceptions=(RuntimeError, TypeError, ValueError),
        terminal_key="sample",
        terminal_record={"status": "done"},
    )

    assert publish_inmemory_partial_results_from_request(request) is False
    assert tuple(key for key, _record in cache.pending_delta().items) == ("sample",)


def test_stage2107_decision_rejects_hostile_force_without_bool_hook(tmp_path) -> None:
    _HostileForce.touched = 0
    logs: list[str] = []

    decision = inmemory_partial_publication_decision(
        partial_output_path=tmp_path / "partial.json",
        results={"sample": {"status": "done"}, "other": {"status": "queued"}},
        partial_output_every=3,
        log_error=logs.append,
        force=_HostileForce(),
    )

    assert decision.should_attempt is False
    assert decision.reason == "partial_publication_not_due"
    assert _HostileForce.touched == 0
    assert any("force" in item and "rejected" in item for item in logs)
