import json
from Virus_Scan.core.jsonio import read_json_file
from Virus_Scan.runtime.structured_failures import clear_failure_records, failure_snapshot
import Virus_Scan.reporting.result_schema as rs


def test_read_json_rejects_semantically_incomplete_queue_failure(tmp_path):

    clear_failure_records()
    p = tmp_path / "job.json"
    p.write_text(json.dumps({"queue_failure": True, "file": "x.bin"}), encoding="utf-8")
    assert read_json_file(p, default=None) == {}
    records = failure_snapshot()["records"]
    assert records
    assert records[0]["domain"] == "persistence"
    assert records[0]["fatal"] is True
    assert records[0]["unsafe_to_continue"] is True


def test_read_json_records_decode_failure_without_returning_default_state(tmp_path):

    clear_failure_records()
    p = tmp_path / "job.json"
    p.write_text('{"queue_failure": true, "failure_info": ', encoding="utf-8")
    assert read_json_file(p, default=None) == {}
    rec = failure_snapshot()["records"][0]
    assert rec["domain"] == "persistence"
    assert rec["fatal"] is True
    assert rec["suppressed"] is True


def test_queue_file_result_final_verify_removes_corrupt_final_directly(tmp_path):

    final = tmp_path / "queue" / "file_results" / "sample.json"
    final.parent.mkdir(parents=True)
    file_path = tmp_path / "sample.bin"
    # Syntactically valid but semantically incomplete result boundary.
    final.write_text(json.dumps({"file": str(file_path), "result": []}), encoding="utf-8")

    assert rs._verify_queue_file_result_final(final, file_path) is False
    assert not final.exists()


def test_queue_file_result_tmp_verify_blocks_nonfinite_payload(tmp_path):

    queue_dir = tmp_path / "queue"
    claim = tmp_path / "claim.json"
    file_path = tmp_path / "sample.bin"
    # The normalizer/json safe path should sanitize nonfinite values before write.
    result = {"file": str(file_path), "tags": [], "score": float("nan"), "classification": "LOW"}
    assert rs.write_queue_file_result(queue_dir, claim, file_path, result) is True
    saved = list((queue_dir / "file_results").glob("*.json"))
    assert saved
    data = json.loads(saved[0].read_text(encoding="utf-8"))
    assert data["result"]["score"] == {"non_finite_float": "nan"}
