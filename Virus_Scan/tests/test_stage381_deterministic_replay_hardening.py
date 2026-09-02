from Virus_Scan.publication.json_writer import finalize_scan_results
from Virus_Scan.scanners.archives import scan_archive_file
from Virus_Scan.scheduler.queue.recovery_snapshot import deterministic_recovery_snapshot

import json
import zipfile


def test_stage381_malformed_declared_archive_reports_explicit_container_failure(tmp_path):

    bad = tmp_path / "broken.zip"
    bad.write_bytes(b"PK\x03\x04 truncated header without central directory")

    tags, suspicious = scan_archive_file(str(bad))

    assert suspicious is True
    assert "malformed_container" in tags
    assert "malformed_zip_container" in tags
    assert "failure_domain_extraction" in tags
    assert "unknown_archive" in tags


def test_stage381_cross_engine_embedded_pe_payload_is_recorded_from_archive_member(tmp_path):

    archive = tmp_path / "renpy_container.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("game/renpy_script.rpy", "label start:\n    return\n")
        zf.writestr("Game_Data/Managed/Assembly-CSharp.dat", b"MZ\0\0BSJB #~ Assembly-CSharp PowerShell Process.Start")

    tags, suspicious = scan_archive_file(str(archive))

    assert suspicious is True
    assert "embedded_pe_payload" in tags
    assert "archive_member_magic_pe" in tags
    assert "embedded_dotnet_payload" in tags
    assert "cross_engine_embedded_payload" in tags


def test_stage381_finalizer_verifies_tmp_and_final_json_before_success(tmp_path):

    output = tmp_path / "scan_results.json"
    results = {
        "b.bin": {"file": "b.bin", "path": "b.bin", "classification": "benign_clean", "score": 0, "tags": []},
        "a.bin": {"file": "a.bin", "path": "a.bin", "classification": "benign_clean", "score": 0, "tags": []},
    }

    assert finalize_scan_results(str(output), results) is True
    loaded = json.loads(output.read_text())
    assert list(loaded.keys()) == ["a.bin", "b.bin"]
    assert all("exit_code" in value for value in loaded.values())


def test_stage381_recovery_snapshot_removes_live_fields_and_sorts_nested_state():

    record = {
        "file": "sample.bin",
        "worker_pid": 999,
        "heartbeat_time": 123.4,
        "queue_info": {"worker_id": "w2", "retry_generation": 2, "b": 1, "a": 2},
        "history": [{"action": "retry", "time": 55.0, "iso": "now", "reason": "killed", "pid": 999}],
    }

    snap = deterministic_recovery_snapshot(record)

    assert "worker_pid" not in snap
    assert "heartbeat_time" not in snap
    assert "worker_id" not in snap["queue_info"]
    assert "time" not in snap["history"][0]
    assert "iso" not in snap["history"][0]
    assert list(snap["queue_info"].keys()) == ["a", "b", "retry_generation"]
