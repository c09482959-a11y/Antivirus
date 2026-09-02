from __future__ import annotations

import json
from pathlib import Path

import pytest

from Virus_Scan.contracts.checkpoint import JsonSafeCheckpointDelta
from Virus_Scan.scheduler.evidence.partial_checkpoint_cache import PartialCheckpointCache
from Virus_Scan.publication.json_finalization.checkpoint_journal import (
    append_checkpoint_delta,
    load_checkpoint_journal,
    materialize_checkpoint_journal,
)
from Virus_Scan.publication.json_finalization.streaming import finalize_scan_results
from Virus_Scan.publication.scan_result_ledger import ScanResultLedgerAccumulator
from Virus_Scan.scheduler.evidence.scheduler_json_partial import write_partial_scheduler_results


def _partial_values(
    *,
    cache: PartialCheckpointCache,
    results: dict[str, object],
    writes: list[object],
    every: int = 100,
    force: bool = False,
) -> dict[str, object]:
    return {
        "partial_output_path": "scan_results.json",
        "results": results,
        "total_files": 100,
        "partial_output_every": every,
        "last_partial_write": 1.0,
        "now": lambda: 4.0,
        "environ_get": lambda _name, default: default,
        "write_partial_scan_results": lambda _path, value, **_kwargs: writes.append(value) or True,
        "make_json_safe": lambda value: value,
        "log_error": lambda _message: None,
        "checkpoint_cache": cache,
        "force": force,
    }


def test_checkpoint_record_is_observed_before_publication_is_due() -> None:
    cache = PartialCheckpointCache()
    writes: list[object] = []
    record = {"score": 1}
    results = {"sample": record, "other": {"score": 2}}

    last = write_partial_scheduler_results(
        **_partial_values(cache=cache, results=results, writes=writes)
    )

    assert last == 1.0
    assert tuple(cache.pending_records) == ("other",)
    assert writes == []


def test_checkpoint_cache_emits_only_new_recovery_records_transactionally() -> None:
    cache = PartialCheckpointCache()
    first_record = {"score": 1}
    second_record = {"score": 2}

    assert cache.observe_terminal("a", first_record, lambda value: value)
    first = cache.pending_delta()
    cache.commit_delta(first)
    assert cache.observe_terminal("b", second_record, lambda value: value)
    second = cache.pending_delta()

    assert tuple(key for key, _record in first.items) == ("a",)
    assert tuple(key for key, _record in second.items) == ("b",)
    assert first.first_sequence == 1 and first.total_records == 1
    assert second.first_sequence == 2 and second.total_records == 2


def test_checkpoint_cache_preserves_pending_delta_after_write_failure() -> None:
    cache = PartialCheckpointCache()
    record = {"score": 1}
    cache.observe_terminal("sample", record, lambda value: value)
    first = cache.pending_delta()

    assert first.items
    assert cache.pending_delta() == first
    cache.commit_delta(first)
    assert cache.pending_delta().items == ()


def test_scheduler_retry_commits_exact_pending_delta_after_writer_failure() -> None:
    cache = PartialCheckpointCache()
    record = {"score": 1}
    writes: list[object] = []
    outcomes = [False, True]

    def writer(_path: str, value: object, **_kwargs: object) -> bool:
        writes.append(value)
        return outcomes.pop(0)

    values = _partial_values(
        cache=cache,
        results={"sample": record},
        writes=[],
        every=1,
        force=True,
    )
    values["write_partial_scan_results"] = writer

    assert write_partial_scheduler_results(**values) == 1.0
    pending = cache.pending_delta()
    assert tuple(key for key, _record in pending.items) == ("sample",)
    assert write_partial_scheduler_results(**values) == 4.0
    assert cache.pending_delta().items == ()
    assert writes == [pending, pending]


def test_checkpoint_cache_rejects_terminal_replacement_and_removal() -> None:
    cache = PartialCheckpointCache()
    record = {"score": 1}
    cache.observe_terminal("sample", record, lambda value: value)

    with pytest.raises(RuntimeError, match="checkpoint_terminal_record_replaced"):
        cache.observe_terminal("sample", {"score": 2}, lambda value: value)

    with pytest.raises(RuntimeError, match="checkpoint_terminal_record_removed"):
        cache.reconcile_results({}, lambda value: value)


def test_append_only_journal_grows_by_delta_and_projects_once(tmp_path: Path) -> None:
    journal = tmp_path / "scan_results.json.partial"
    checkpoint = tmp_path / "scan_results.json.partial.checkpoint.json"
    first = JsonSafeCheckpointDelta((("a", {"score": 1}),), 1, 1)
    second = JsonSafeCheckpointDelta((("b", {"score": 2}),), 2, 2)

    assert append_checkpoint_delta(journal, first)
    first_size = journal.stat().st_size
    assert append_checkpoint_delta(journal, second)
    second_size = journal.stat().st_size

    assert second_size > first_size
    assert second_size < first_size * 3
    assert load_checkpoint_journal(journal) == {"a": {"score": 1}, "b": {"score": 2}}
    with journal.open("a", encoding="utf-8") as stream:
        stream.write('{"kind":"record","schema_version":"partial_checkpoint_journal_v2"')
    assert load_checkpoint_journal(journal) == {"a": {"score": 1}, "b": {"score": 2}}
    third = JsonSafeCheckpointDelta((("c", {"score": 3}),), 3, 3)
    assert append_checkpoint_delta(journal, third)
    assert load_checkpoint_journal(journal) == {
        "a": {"score": 1},
        "b": {"score": 2},
        "c": {"score": 3},
    }
    assert materialize_checkpoint_journal(journal, checkpoint) == 3
    assert json.loads(checkpoint.read_text(encoding="utf-8")) == {
        "a": {"score": 1},
        "b": {"score": 2},
        "c": {"score": 3},
    }


def test_finalization_observes_exact_compact_records_without_reread(tmp_path: Path) -> None:
    output = tmp_path / "scan_results.json"
    ledger = ScanResultLedgerAccumulator()
    results = {"sample": {"classification": "malicious", "score": 92, "tags": ["script"]}}

    assert finalize_scan_results(
        str(output),
        results,
        ledger_accumulator=ledger,
    )

    final = json.loads(output.read_text(encoding="utf-8"))
    assert len(ledger.payloads) == 1
    assert ledger.payloads[0]["record_digest"]
    assert ledger.payloads[0]["score"] == final["sample"]["score"]


def test_checkpoint_journal_identical_committed_retry_is_noop(tmp_path: Path) -> None:
    journal = tmp_path / "scan_results.json.partial"
    delta = JsonSafeCheckpointDelta(
        (("a", {"score": 1}), ("b", {"score": 2})),
        1,
        2,
    )

    assert append_checkpoint_delta(journal, delta)
    committed_size = journal.stat().st_size
    assert append_checkpoint_delta(journal, delta)

    assert journal.stat().st_size == committed_size
    assert load_checkpoint_journal(journal) == {
        "a": {"score": 1},
        "b": {"score": 2},
    }


def test_checkpoint_journal_rejects_divergent_overlap_and_sequence_gap(
    tmp_path: Path,
) -> None:
    journal = tmp_path / "scan_results.json.partial"
    assert append_checkpoint_delta(
        journal,
        JsonSafeCheckpointDelta((("a", {"score": 1}),), 1, 1),
    )

    with pytest.raises(RuntimeError, match="checkpoint_journal_sequence_conflict"):
        append_checkpoint_delta(
            journal,
            JsonSafeCheckpointDelta((("a", {"score": 9}),), 1, 1),
        )
    with pytest.raises(RuntimeError, match="checkpoint_journal_sequence_conflict"):
        append_checkpoint_delta(
            journal,
            JsonSafeCheckpointDelta((("c", {"score": 3}),), 3, 3),
        )

    assert load_checkpoint_journal(journal) == {"a": {"score": 1}}
