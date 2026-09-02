from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path


import pytest

from Virus_Scan.scheduler.queue.publication_state import (
    QueuePublicationState,
    QueueRunFinalizationState,
    _publication_identity_set,
    _publication_text,
    _result_publication_file_identity,
)
from Virus_Scan.scheduler.queue.snapshots import QueuePhaseLedger


class HostileValue:
    def __bool__(self):
        raise AssertionError("bool hook executed")

    def __str__(self):
        raise AssertionError("str hook executed")

    def __format__(self, spec):
        raise AssertionError("format hook executed")

    def __iter__(self):
        raise AssertionError("iter hook executed")


def test_publication_text_rejects_hostile_field_and_value_without_hooks():
    with pytest.raises(RuntimeError, match="scheduler_publication_field_rejected"):
        _publication_text(HostileValue(), field_name=HostileValue())

    with pytest.raises(ValueError, match="scheduler_publication_field_container_rejected"):
        _publication_identity_set(HostileValue(), field_name=HostileValue())


def test_publication_duplicate_and_archive_identity_use_owned_text(tmp_path: Path):
    first = {"job_id": "job-1", "file": str(tmp_path / "a.bin")}
    state = QueuePublicationState.empty().with_publication(first)

    archive = _result_publication_file_identity(
        {"job_id": "job-2", "file": str(tmp_path / "b.bin"), "archive_member": "inner"}
    )
    assert archive.endswith("::inner")

    with pytest.raises(RuntimeError, match="duplicate scheduler result publication: job-1"):
        state.with_publication({"job_id": "job-1", "file": str(tmp_path / "c.bin")})


def test_finalization_count_projection_rejects_hostile_and_reports_exact_mismatch():
    with pytest.raises(ValueError, match="scheduler_emitted_result_count_rejected"):
        QueueRunFinalizationState(
            phase_ledger=QueuePhaseLedger(()),
            publication_state=QueuePublicationState.empty(),
            worker_failures=(),
            emitted_result_count=HostileValue(),
            finalized_count=0,
        )

    state = QueueRunFinalizationState(
        phase_ledger=QueuePhaseLedger(()),
        publication_state=QueuePublicationState.empty(),
        worker_failures=(),
        emitted_result_count=1,
        finalized_count=0,
    )
    with pytest.raises(RuntimeError, match="scheduler finalization result mismatch: emitted=1 finalized=0"):
        state.assert_valid()


def test_publication_state_source_has_no_repaired_fstrings_or_fallback_routes():
    source = read_python_file(Path("Virus_Scan/scheduler/queue/publication_state.py"))
    forbidden = (
        'unsupported_reason=f"scheduler_publication_{field_name}_rejected"',
        'f"scheduler_publication_{field_name}_missing"',
        'f"{base_identity}::{archive_identity}"',
        'f"duplicate scheduler result publication: {job_identity}"',
        'f"duplicate scheduler file result publication: {file_identity}"',
        'f"scheduler finalization result mismatch:',
        'f"scheduler_publication_{field_name}_container_rejected"',
        "fallback=0",
    )
    for pattern in forbidden:
        assert pattern not in source
