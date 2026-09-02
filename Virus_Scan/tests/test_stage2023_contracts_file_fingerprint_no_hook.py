from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.contracts import file_fingerprint



class HostileNumeric:
    touched = 0

    def __int__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned int hook was invoked")

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned text hook was invoked")


def test_stage2023_file_fingerprint_int_status_records_parse_reason() -> None:
    assert file_fingerprint._safe_int_status("not-an-int") == (0, "parse_error")
    assert file_fingerprint._safe_int("not-an-int") == 0


def test_stage2023_file_fingerprint_int_status_rejects_hostile_hooks() -> None:
    HostileNumeric.touched = 0

    assert file_fingerprint._safe_int_status(HostileNumeric()) == (0, "unsafe_fingerprint_int_rejected")
    assert HostileNumeric.touched == 0


def test_stage2023_file_fingerprint_source_removed_backlog_snippet() -> None:
    source = read_python_file(Path("Virus_Scan/contracts/file_fingerprint.py"))

    assert "except (TypeError, ValueError, OverflowError):\n        return 0" not in source
