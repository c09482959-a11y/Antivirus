"""Stage1700 scanner PE parse-result no-hook boundary regressions."""
from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

from Virus_Scan.scanners import binary_pe_sections


class HostileTextValue:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def _touch(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned PE import text hook executed")

    def __str__(self):
        return self._touch()

    def __repr__(self):
        return self._touch()

    def __format__(self, spec):
        return self._touch()

    def __bool__(self):
        return self._touch()


class HostileImportNames:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned PE import names bool executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned PE import names iter executed")


class HostileImportSequence:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned PE import sequence bool executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned PE import sequence iter executed")


class HostileSectionRecord:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned PE section bool executed")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned PE section mapping items executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned PE section iter executed")



def test_stage1700_pe_import_result_rejects_hostile_module_and_name_without_hooks():
    HostileTextValue.reset()

    result = binary_pe_sections.PEImportParseResult(
        imports=((HostileTextValue(), (HostileTextValue(),)),)
    )

    assert HostileTextValue.touched == 0
    assert result.imports == ()
    assert "pe_import_result_materialize_scan_error" in result.error_tags
    assert "scanner_failure_evidence:binary:pe_import_result_materialize" in result.error_tags



def test_stage1700_pe_import_result_rejects_hostile_names_container_without_hooks():
    HostileImportNames.reset()

    result = binary_pe_sections.PEImportParseResult(
        imports=(("kernel32.dll", HostileImportNames()),)
    )

    assert HostileImportNames.touched == 0
    assert result.imports == (("kernel32.dll", ()),)
    assert "pe_import_result_materialize_scan_error" in result.error_tags
    assert "scanner_failure_evidence:binary:pe_import_result_materialize" in result.error_tags



def test_stage1700_pe_import_result_rejects_hostile_import_sequence_without_hooks():
    HostileImportSequence.reset()

    result = binary_pe_sections.PEImportParseResult(imports=HostileImportSequence())

    assert HostileImportSequence.touched == 0
    assert result.imports == ()
    assert "pe_import_result_materialize_scan_error" in result.error_tags
    assert "scanner_failure_evidence:binary:pe_import_result_materialize" in result.error_tags



def test_stage1700_pe_section_result_rejects_hostile_section_without_hooks():
    HostileSectionRecord.reset()

    result = binary_pe_sections.PESectionParseResult(sections=(HostileSectionRecord(),))

    assert HostileSectionRecord.touched == 0
    assert len(result.sections) == 1
    assert result.sections[0]["unavailable_reason"] == "unsupported_scanner_contract_value"
    assert "pe_section_result_materialize_scan_error" in result.error_tags
    assert "scanner_failure_evidence:binary:pe_section_result_materialize" in result.error_tags



def test_stage1700_pe_parse_results_preserve_exact_owned_values():
    import_result = binary_pe_sections.PEImportParseResult(
        imports=(("kernel32.dll", ("CreateFileW", "ReadFile")),)
    )
    section_result = binary_pe_sections.PESectionParseResult(
        sections=({"name": ".text", "entropy": 6.0, "raw_size": 10},)
    )

    assert import_result.imports == (("kernel32.dll", ("CreateFileW", "ReadFile")),)
    assert import_result.error_tags == ()
    assert section_result.sections == (MappingProxyType({"entropy": 6.0, "name": ".text", "raw_size": 10}),)
    assert section_result.error_tags == ()



def test_stage1700_pe_parse_result_source_has_no_unsafe_result_conversions():
    source = Path(binary_pe_sections.__file__).read_text(encoding="utf-8")

    forbidden = (
        "str(module)",
        "str(name)",
        "names or",
        "self.imports or",
        "section or {}",
        "self.sections or",
    )
    for pattern in forbidden:
        assert pattern not in source
