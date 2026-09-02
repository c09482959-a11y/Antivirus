import json
import threading


from Virus_Scan.runtime.structured_failures import clear_failure_records, record_suppressed_failure, failure_snapshot
from Virus_Scan.runtime.structured_failures import clear_failure_records, record_suppressed_failure, canonical_failure_snapshot
from Virus_Scan.core.jsonio import read_json_file
from Virus_Scan.runtime.structured_failures import clear_failure_records, failure_snapshot
from Virus_Scan.runtime.provenance import stable_digest

def test_failure_snapshot_thread_safe_and_contains_provenance():
    clear_failure_records()
    def worker(i):
        try:
            raise ValueError(f"queue json write failed {i % 3}")
        except ValueError as exc:
            record_suppressed_failure(
                "queue_json_replace",
                exc,
                domain="scheduler",
                context={"queue_identity": "sample.bin", "retry_generation": i % 2, "worker_identity": f"w{i%4}"},
            )
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(64)]
    for t in threads: t.start()
    for t in threads: t.join()
    snap = failure_snapshot()
    assert snap["records"]
    for rec in snap["records"]:
        assert rec["provenance"]["schema_version"] == 1
        assert rec["provenance"]["origin_subsystem"] == "scheduler"
        assert rec["provenance"]["queue_identity"] == "sample.bin"
        assert rec["unsafe_to_continue"] is True
        assert rec["fatal"] is True
        assert rec["fingerprint"]
        assert rec["correlation_id"]


def test_canonical_failure_snapshot_strips_runtime_volatility():
    clear_failure_records()
    record_suppressed_failure("json_read_semantic_validation_failed", ValueError("bad schema"), domain="persistence", context={"file":"a.json", "attempt": 1})
    first = canonical_failure_snapshot()
    clear_failure_records()
    record_suppressed_failure("json_read_semantic_validation_failed", ValueError("bad schema"), domain="persistence", context={"file":"a.json", "attempt": 1})
    second = canonical_failure_snapshot()
    assert first == second
    assert first["records"][0]["provenance"]["queue_identity"] == "a.json"


def test_queue_json_semantic_failure_records_provenance(tmp_path):
    clear_failure_records()
    p = tmp_path / "bad_queue.json"
    p.write_text(json.dumps({"queue_failure": True}), encoding="utf-8")
    assert read_json_file(p, default={"default": True}) == {"default": True}
    recs = failure_snapshot()["records"]
    assert recs
    assert any(r["fatal"] and r["unsafe_to_continue"] for r in recs)
    assert any(r["provenance"]["origin_subsystem"] == "persistence" for r in recs)


def test_failure_provenance_stable_digest_ignores_volatile_fields():
    a = {"file":"x", "time":1, "heartbeat_time":5, "attempt":2}
    b = {"file":"x", "time":999, "heartbeat_time":123, "attempt":2}
    assert stable_digest(a) == stable_digest(b)
