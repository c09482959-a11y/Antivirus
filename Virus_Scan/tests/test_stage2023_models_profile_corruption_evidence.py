from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.models.profiles import corruption


def test_stage2023_profile_corruption_bytes_failure_records_unavailable_token() -> None:
    view = memoryview(bytearray(b"profile"))
    view.release()

    safe = corruption.profile_corruption_json_safe(view)

    assert safe == "profile_corruption_text_unavailable:memoryview"


def test_stage2023_profile_corruption_source_has_no_decode_exception_sentinel() -> None:
    source = read_python_file(Path("Virus_Scan/models/profiles/corruption.py"))
    detached = source.split("def _profile_detached_text", 1)[1].split("def _profile_text_from_attrs", 1)[0]

    assert "except RECOVERABLE_RUNTIME_ERRORS:\n            return None" not in detached
    assert "_PROFILE_TEXT_UNAVAILABLE + ':' + no_hook_type_name(value)" in detached
