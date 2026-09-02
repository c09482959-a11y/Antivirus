import inspect
from pathlib import Path

from Virus_Scan.core import jsonio


def test_corrupt_json_quarantine_success_preserves_evidence_file(tmp_path):
    corrupt = tmp_path / "bad.json"
    corrupt.write_text('{"truncated": ', encoding="utf-8")

    quarantined = jsonio._quarantine_corrupt_json_file(
        str(corrupt),
        reason="unit corrupt json",
        log_context="stage988",
    )

    assert quarantined is not None
    quarantine_path = Path(quarantined)
    assert quarantine_path.exists()
    assert quarantine_path.read_text(encoding="utf-8") == '{"truncated": '
    assert not corrupt.exists()


def test_corrupt_json_quarantine_failure_is_recorded_without_copy_path():
    source = inspect.getsource(jsonio._quarantine_corrupt_json_file)

    assert "jsonio_corrupt_quarantine_replace_failed" in source
    assert "jsonio_corrupt_quarantine_failed" in source
    assert "shutil.copy2" not in source
    assert "jsonio_corrupt_quarantine_copy_failed" not in source
    assert source.count("_jsonio_record_degraded") >= 4
