from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.runtime.provenance import _safe_text, stable_digest



class ValueErrorString:
    def __str__(self) -> str:
        raise ValueError("cannot stringify")


class RuntimeErrorJson:
    def __iter__(self):
        raise RuntimeError("cannot iterate")


def test_stage1012_safe_text_uses_bounded_exception_conversion() -> None:
    assert _safe_text(ValueErrorString()) == "<unprintable>"


def test_stage1012_stable_digest_preserves_bounded_fallback_behavior() -> None:
    digest = stable_digest({"payload": ValueErrorString()})
    assert isinstance(digest, str)
    assert len(digest) == 24


def test_stage1012_runtime_provenance_has_no_baseexception_handlers() -> None:
    source = read_python_file(Path("Virus_Scan/runtime/provenance.py"))
    assert "except BaseException" not in source
    assert "_PROVENANCE_TEXT_ERRORS" in source
    assert "_PROVENANCE_JSON_ERRORS" in source
