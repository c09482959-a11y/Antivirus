import inspect

from Virus_Scan.contracts.result_record import INCOMPLETE_SCAN_TAGS, scanner_degraded_tags, degraded_scan_integrity
from Virus_Scan.scanners import entropy, dotnet, ilspy, strings
from Virus_Scan.scheduler.queue import integrity as raw_queue_integrity
from Virus_Scan.scheduler.queue.raw_integrity import apply_integrity_tags


def test_contract_exposes_scanner_degraded_tag_helper():
    tags = scanner_degraded_tags(["existing"], "extra")
    assert "existing" in tags
    assert "extra" in tags
    assert set(INCOMPLETE_SCAN_TAGS).issubset(set(tags))
    integrity = degraded_scan_integrity("boom", scanner="unit")
    assert integrity["allow_learning"] is False
    assert integrity["had_degraded_stage"] is True
    assert integrity["file_failed"] is True


def test_entropy_empty_or_failed_read_is_degraded(tmp_path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    res = entropy.detect_packer_entropy_anomaly(str(empty))
    assert set(INCOMPLETE_SCAN_TAGS).issubset(set(res["tags"]))
    assert res["scan_integrity"]["allow_learning"] is False

    res = entropy.detect_packer_entropy_anomaly(str(tmp_path / "locked_missing.bin"))
    assert "entropy_scan_error" in res["tags"]
    assert set(INCOMPLETE_SCAN_TAGS).issubset(set(res["tags"]))
    assert res["scan_integrity"]["allow_learning"] is False


def test_dotnet_preread_failures_do_not_return_empty_clean():
    def boom(*a, **k):
        raise OSError("locked")
    tags, meta = dotnet.scan_unity_dotnet_layered_file("locked.dll", read_bytes=boom, logger=lambda *a, **k: None)
    assert "unity_dotnet_layered_scan_error" in tags
    assert set(INCOMPLETE_SCAN_TAGS).issubset(set(tags))
    assert meta["scan_integrity"]["allow_learning"] is False

    tags, meta = dotnet.scan_unity_ilspy_file("locked.dll", read_bytes=boom)
    assert set(INCOMPLETE_SCAN_TAGS).issubset(set(tags))
    assert meta["scan_integrity"]["allow_learning"] is False

    should, ctx = dotnet.unity_ilspy_should_run("locked.dll", read_bytes=boom)
    assert should is False
    assert ctx["reason"] == "preread_failed"
    assert ctx["scan_integrity"]["allow_learning"] is False


def test_string_scanner_failure_is_explicitly_degraded():
    def boom(*a, **k):
        raise RuntimeError("context scanner died")
    tags = strings.scan_strings(strings.ScanStringsRequest(
        "abc",
        path="bad.txt",
        finalize=True,
        contextual_scanner=boom,
        payload_decoder=lambda *a, **k: [],
        finalizer=lambda tags, **k: list(tags),
    ))
    assert "string_scan_error" in tags
    assert set(INCOMPLETE_SCAN_TAGS).issubset(set(tags))


def test_raw_integrity_missing_chunks_forces_incomplete_tags():
    integrity = {"raw_expected": 4, "raw_completed": 2, "missing_chunks": 2, "raw_failed": 0, "had_degraded_stage": True}
    tags = apply_integrity_tags(["global_raw_queue_scan"], integrity, scanner_degraded_tags=scanner_degraded_tags)
    assert set(INCOMPLETE_SCAN_TAGS).issubset(set(tags))
    assert "raw_accumulator_incomplete" in tags


def test_no_known_window6_failopen_source_patterns_remain():
    for module in (entropy, dotnet, strings, raw_queue_integrity):
        src = inspect.getsource(module)
        assert '"tags": []' not in src
    assert "not_dotnet_or_not_enabled" in inspect.getsource(ilspy)
