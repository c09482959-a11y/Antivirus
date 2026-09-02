import os
from pathlib import Path

from Virus_Scan.scheduler.queue import claim as pqe
import Virus_Scan.scheduler.queue.process_queue_finalization as pqf
from Virus_Scan.scheduler.context import inmemory_raw_dependency_factory as raw_deps
from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scanners import raw_chunk_collectors as rcp
import Virus_Scan.scheduler.queue.feed_marker as pqfm
import Virus_Scan.scheduler.evidence.process_queue_errors as pq_errors


def test_stage125_finish_cleanup_failures_are_process_queue_attributed(tmp_path):
    q = tmp_path / "q"
    pending, active, done, failed = pqe._queue_job_dirs(q)
    for d in (pending, active, done, failed):
        d.mkdir(parents=True, exist_ok=True)
    claim = active / "worker_job.json"
    claim.write_text('{"file":"x.bin"}', encoding="utf-8")
    calls = []
    assert pqf._finish_process_queue_job(
        q,
        claim,
        ok=True,
        job={"file": "x.bin"},
        record_suppressed=lambda where, exc, **kw: calls.append((where, type(exc).__name__, kw)),
        remove_claim_meta=lambda *a, **k: (_ for _ in ()).throw(OSError("sidecar cleanup failed")),
    ) is True

    names = [c[0] for c in calls]
    assert "queue_finish_pre_move_claim_meta_cleanup_failed" in names
    assert "queue_finish_post_move_claim_meta_or_index_cleanup_failed" in names or "queue_finish_orphan_claim_cleanup_failed" in names
    assert (done / claim.name).exists()


def test_stage125_feed_complete_tmp_cleanup_failure_is_attributed(tmp_path):
    calls = []
    queue_dir = tmp_path / "q"
    queue_dir.mkdir()
    (queue_dir / "feed_complete.marker").mkdir()
    assert pqfm.mark_process_queue_feed_complete(
        queue_dir,
        safe_unlink=lambda *a, **k: (_ for _ in ()).throw(OSError("unlink failed")),
        record_suppressed=lambda where, exc, **kw: calls.append((where, type(exc).__name__, kw)),
    ) is False

    names = [c[0] for c in calls]
    assert "queue_feed_complete_tmp_cleanup_failed" in names
    assert "queue_feed_complete_persist_failed" in names


def test_stage125_bytecode_context_failure_uses_collector_specific_provenance(tmp_path):
    sample = tmp_path / "script.py"
    sample.write_text("eval(" + "A" * 128, encoding="utf-8")
    calls = []
    out = rcp.bytecode_chunk(
        rcp.BytecodeChunkRequest(
            sample,
            0,
            4096,
            raw_deps._global_raw_read_range_text,
            raw_deps.get_scan_extension,
            raw_deps.detect_python_pickle_opcode_exec,
            lambda text: True,
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("ctx failed")),
            lambda tags, collector, exc, **kw: raw_deps._raw_collector_context_failure_impl(
                tags, collector, exc, report=lambda stage, exc, **inner: calls.append((stage, type(exc).__name__, inner.get("extra", {}))), scanner_degraded_tags=raw_deps._contract_scanner_degraded_tags, **kw
            ),
            raw_deps._record_process_queue_suppressed,
            RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
        )
    )

    assert "scanner_failure" in out["tags"]
    assert calls and calls[0][0] == "raw_bytecode_chunk_context_scan_failed"
    assert calls[0][2]["collector"] == "bytecode_chunk"


def test_stage125_dotnet_context_failure_uses_collector_specific_provenance(tmp_path):
    sample = tmp_path / "managed.dll"
    sample.write_text("mscoree.dll #strings #us #blob " + "A" * 128, encoding="utf-8")
    calls = []
    out = rcp.dotnet_chunk(
        rcp.ContextualRawChunkRequest(
            sample,
            0,
            4096,
            raw_deps._global_raw_read_range_text,
            lambda text: True,
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("ctx failed")),
            lambda tags, collector, exc, **kw: raw_deps._raw_collector_context_failure_impl(
                tags, collector, exc, report=lambda stage, exc, **inner: calls.append((stage, type(exc).__name__, inner.get("extra", {}))), scanner_degraded_tags=raw_deps._contract_scanner_degraded_tags, **kw
            ),
        )
    )

    assert "scanner_failure" in out["tags"]
    assert calls and calls[0][0] == "raw_dotnet_chunk_context_scan_failed"
    assert calls[0][2]["collector"] == "dotnet_chunk"


def test_stage125_process_queue_engine_does_not_reference_unbound_telemetry_names():
    assert callable(pq_errors.process_queue_record_suppressed)
    assert "record_scheduler_suppressed('suppressed_exception'" not in Path(pqf.__file__).read_text(encoding="utf-8").split("def _finish_process_queue_job", 1)[1].split("# Process-queue feed completion is owned", 1)[0]
