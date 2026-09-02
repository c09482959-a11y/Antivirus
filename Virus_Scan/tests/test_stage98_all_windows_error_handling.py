import math
import random
import json
from pathlib import Path


from Virus_Scan.scheduler.internal.output_publication import write_worker_output_payload
from Virus_Scan.scheduler.runtime import queue_filesystem
from Virus_Scan.scheduler.runtime.queue_json_replace_commit import queue_json_verify_target
from Virus_Scan.scheduler.runtime.queue_json_schema import verify_persistent_json_file
from Virus_Scan.scheduler.internal.exception_projection import scheduler_exception_text
from Virus_Scan.contracts.result_record import normalize_result_record, result_is_cache_reusable, result_is_incomplete_scan
from Virus_Scan.contracts.worker_record import make_json_safe

def test_worker_fast_output_removes_destination_on_post_replace_corruption(tmp_path):
    blocked_parent = tmp_path / "worker-output-parent"
    blocked_parent.write_text("not a directory", encoding="utf-8")
    target = blocked_parent / "worker.json"

    assert write_worker_output_payload(str(target), {"file": "x", "score": 1}) is False
    assert not target.exists()


def _assert_corrupt_queue_target_removed(target: Path, text: str) -> None:
    target.write_text(text, encoding="utf-8")
    expected = {"schema_version": 1, "job_type": "unit", "value": 1}
    assert queue_json_verify_target(
        target,
        expected,
        safe_context="stage98_corrupt_queue_target",
        verify_required=True,
        safe_unlink=queue_filesystem.queue_safe_unlink,
        verify_file_func=verify_persistent_json_file,
        log_func=lambda _message: None,
        exception_text_func=scheduler_exception_text,
        record_degraded=lambda *_args, **_kwargs: None,
    ) is False
    assert not target.exists()


def test_queue_verified_write_removes_non_object_corruption(tmp_path):

    target = tmp_path / "queue_job.json"
    _assert_corrupt_queue_target_removed(target, '["not", "an", "object"]')
    assert not target.exists()


def test_queue_verified_write_removes_mismatched_corruption(tmp_path):

    target = tmp_path / "queue_job.json"
    _assert_corrupt_queue_target_removed(target, '{"schema_version":1,"job_type":"unit","value":999}')
    assert not target.exists()


def test_all_window_error_contract_fuzz_10000(tmp_path):

    rng = random.Random(9810)
    for i in range(10000):
        rec = {
            "file": f"window_{rng.randint(1,10)}_{i}.bin",
            "tags": rng.choice([None, "scanner_failure", ["url_present"], ["scanner_degraded"], {"a", "b"}, 17]),
            "classification": rng.choice(["clean", "error", "timeout", "asset", None]),
            "score": rng.choice([0, 1, math.nan, math.inf, -math.inf]),
        }
        if rng.random() < 0.35:
            rec["scan_integrity"] = rng.choice([
                {"had_degraded_stage": True},
                {"allow_learning": False},
                {"missing_chunks": True},
                "bad_integrity_shape",
            ])
        if rng.random() < 0.2:
            rec["error"] = "injected error path"
        norm = normalize_result_record(rec, file_path=rec["file"], source="stage98_all_windows")
        safe = make_json_safe(norm)
        assert isinstance(safe, dict)
        json.dumps(safe, allow_nan=False)
        if result_is_incomplete_scan(norm):
            assert result_is_cache_reusable(norm) is False
