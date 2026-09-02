import json
import random
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


from Virus_Scan.contracts.result_record import normalize_result_record, result_is_incomplete_scan, scanner_degraded_tags
from Virus_Scan.core.jsonio import atomic_json_save
from Virus_Scan.scheduler.internal.output_publication import write_worker_output_payload
from Virus_Scan.contracts.result_record import result_is_cache_reusable
from Virus_Scan.scheduler.runtime.queue_json import _queue_write_json_replace
from Virus_Scan.scheduler.runtime import queue_filesystem
from Virus_Scan.scheduler.runtime.queue_json_replace_commit import queue_json_verify_target
from Virus_Scan.scheduler.runtime.queue_json_schema import verify_persistent_json_file
from Virus_Scan.scheduler.internal.exception_projection import scheduler_exception_text

def test_single_string_degraded_tag_not_split_and_blocks_reuse():

    tags = scanner_degraded_tags("scanner_failure")
    assert tags == ["scanner_failure", "scanner_degraded", "scan_incomplete"]
    rec = normalize_result_record({"file": "bad.bin", "tags": "scanner_failure", "class": "clean"}, file_path="bad.bin", source="unit")
    assert "scanner_failure" in rec["tags"]
    assert "s" not in rec["tags"]
    assert result_is_incomplete_scan(rec)
    assert rec.get("learn_eligible") is False


def test_strict_json_sanitizes_nonfinite_values_in_atomic_save(tmp_path):

    target = tmp_path / "state.json"
    assert atomic_json_save(target, {"score": float("nan"), "inf": float("inf"), "ok": 1}, backups=0)
    raw = target.read_text(encoding="utf-8")
    assert "NaN" not in raw and "Infinity" not in raw
    data = json.loads(raw)
    assert data["score"]["non_finite_float"] == "nan"
    assert data["inf"]["non_finite_float"] == "inf"


def test_worker_output_fast_strict_json_and_readback(tmp_path):

    target = tmp_path / "worker.json"
    assert write_worker_output_payload(str(target), {"file": "x", "score": float("nan")})
    raw = target.read_text(encoding="utf-8")
    assert "NaN" not in raw
    assert json.loads(raw)["score"]["non_finite_float"] == "nan"


def test_queue_write_verify_rejects_post_replace_corruption(tmp_path):

    target = tmp_path / "job.json"
    target.write_text('{"schema_version":999,"corrupt":true}', encoding="utf-8")
    expected = {"schema_version": 1, "job_type": "unit", "value": 1}

    assert queue_json_verify_target(
        target,
        expected,
        safe_context="unit_corrupt",
        verify_required=True,
        safe_unlink=queue_filesystem.queue_safe_unlink,
        verify_file_func=verify_persistent_json_file,
        log_func=lambda _message: None,
        exception_text_func=scheduler_exception_text,
        record_degraded=lambda *_args, **_kwargs: None,
    ) is False
    assert not target.exists()


def test_10000_randomized_error_contract_scenarios(tmp_path):

    rng = random.Random(9700)
    tag_shapes = [None, [], "scanner_failure", ["url_present"], ["scanner_degraded"], ("scan_incomplete",), {"x", "y"}]
    classes = [None, "clean", "benign_clean", "error", "timeout", "incomplete_scan", "asset"]
    for i in range(10000):
        tags = rng.choice(tag_shapes)
        cls = rng.choice(classes)
        rec = {"file": f"f{i}.bin", "tags": tags, "classification": cls, "score": rng.choice([0, 1.0, float("nan"), float("inf")])}
        if rng.random() < 0.2:
            rec["error"] = "injected failure"
        if rng.random() < 0.2:
            rec["scan_integrity"] = {"had_degraded_stage": True, "allow_learning": False}
        norm = normalize_result_record(rec, file_path=rec["file"], source="fuzz10000")
        assert isinstance(norm, dict)
        assert isinstance(norm.get("tags"), list)
        raw = json.dumps(norm, default=str)
        assert "scanner_failure" not in raw or result_is_incomplete_scan(norm)
        if result_is_incomplete_scan(norm):
            assert not result_is_cache_reusable(norm)
        if i % 1000 == 0:
            target = tmp_path / f"state_{i}.json"
            assert atomic_json_save(target, norm, backups=0)
            json.loads(target.read_text(encoding="utf-8"))


def test_concurrent_verified_queue_writes_are_strict_json(tmp_path):

    def write_one(i):
        p = tmp_path / f"job_{i:04d}.json"
        ok = _queue_write_json_replace(p, {"job_type": "unit", "i": i, "score": float("nan") if i % 11 == 0 else i}, verify=True, log_context="stage97_concurrent")
        if not ok:
            return False
        data = json.loads(p.read_text(encoding="utf-8"))
        return isinstance(data, dict) and data.get("i") == i and "NaN" not in p.read_text(encoding="utf-8")

    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(write_one, range(128)))
    assert all(results)
