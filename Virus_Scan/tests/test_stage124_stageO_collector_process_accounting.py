import inspect

from Virus_Scan.scheduler.context import inmemory_raw_dependency_factory as raw_deps
from Virus_Scan.scheduler.context import inmemory_raw_policy_dependencies as raw_policy
from Virus_Scan.core.paths import _queue_job_dirs
from Virus_Scan.scheduler.runtime.queue_filesystem import safe_queue_listdir as _safe_queue_listdir
from Virus_Scan.scheduler.runtime.queue_json import read_json_file as _queue_read_json_file
from Virus_Scan.scheduler.queue import raw_queue_counts as raw_counts
from Virus_Scan.scanners import raw_chunk_engine_collectors as rcp
from Virus_Scan.scheduler.queue import raw_queue_identity as rqi
from Virus_Scan.scheduler.queue import identity_lock as queue_identity_lock


def test_stage124_unity_dotnet_il_pipeline_failure_has_valid_telemetry(tmp_path):
    sample = tmp_path / "unity.bin"
    sample.write_text("Assembly-CSharp UnityEngine MonoBehaviour", encoding="utf-8")
    def boom(*args, **kwargs):
        raise RuntimeError("il analyzer failed")
    calls = []
    out = rcp.unity_dotnet_chunk(
        sample,
        start=0,
        size=4096,
        read_range_text_func=raw_deps._global_raw_read_range_text,
        extract_il_patterns=lambda text: ["CALL"],
        analyze_il_pipeline=boom,
        should_context_scan_func=lambda text: False,
        contextual_scan=raw_deps.contextual_tag_scan,
        context_failure=lambda tags, collector, exc, **kw: raw_deps._raw_collector_context_failure_impl(tags, collector, exc, **kw),
        report_issue=lambda stage, exc, **kw: calls.append((stage, type(exc).__name__, kw)),
    )

    assert "unity_managed" in out["tags"]
    assert ("raw_unity_dotnet_il_pipeline_failed", "RuntimeError") in [(c[0], c[1]) for c in calls]
    assert calls[0][2]["extra"]["collector"] == "unity_dotnet_chunk"


def test_stage124_intrastage_decode_failure_returns_degraded_tags(tmp_path):
    sample = tmp_path / "payload.txt"
    def boom(*args, **kwargs):
        raise RuntimeError("decoder failed")
    calls = []
    tags = raw_policy.decoded_chunk_tags_raw(
        "A" * 120,
        path=sample,
        offset=12,
        decoded_payload_tags_func=boom,
        report_issue=lambda stage, exc, **kw: calls.append((stage, type(exc).__name__, kw.get("fatal"))),
        decode_anchors=("A",),
    )

    assert "raw_decoded_chunk_failed" in tags
    assert "scanner_failure" in tags
    assert ("intrastage_decoded_chunk_failed", "RuntimeError", False) in calls


def test_stage124_identity_lock_unexpected_failure_fails_closed(tmp_path):
    not_a_directory = tmp_path / "queue-file"
    not_a_directory.write_text("occupied", encoding="utf-8")

    decision = queue_identity_lock.acquire_identity_lock_decision(
        not_a_directory,
        "file:abc",
    )

    assert decision.acquired is False
    assert decision.lock_path is None
    assert decision.reason == "process_queue_identity_lock_failed_closed"


def test_stage124_pending_file_jobs_unknown_is_not_zero(tmp_path):
    q = tmp_path / "q"
    calls = []
    bad_listdir = lambda path: (_ for _ in ()).throw(OSError("pending unreadable"))

    report = lambda stage, exc, **kw: calls.append((stage, type(exc).__name__, kw.get("fatal")))
    value = raw_counts.pending_file_jobs(q, queue_job_dirs=_queue_job_dirs, safe_listdir=bad_listdir, read_json_file=_queue_read_json_file, report=report)

    assert value == -1
    assert ("raw_pending_file_jobs_unknown", "OSError", False) in calls


def _stage124_pending_file_jobs_canonical_call(queue_dir):
    return raw_counts.pending_file_jobs(
        queue_dir,
        queue_job_dirs=_queue_job_dirs,
        safe_listdir=_safe_queue_listdir,
        read_json_file=_queue_read_json_file,
        report=raw_deps._record_raw_queue_issue,
    )


def test_stage124_targeted_stageO_functions_do_not_use_unattributed_broad_handlers():
    for fn in (
        rcp.unity_dotnet_chunk,
        raw_deps._decoded_chunk_tags_raw,
        queue_identity_lock.acquire_identity_lock_decision,
        _stage124_pending_file_jobs_canonical_call,
    ):
        src = inspect.getsource(fn)
        assert "except Exception" not in src
        assert "monitor_loop_suppressed" not in src
