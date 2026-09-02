"""Stage1699 scanner PE section no-hook boundary regressions."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.scanners import binary_pe_surface


class HostileSectionValue:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def _touch(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned PE section hook executed")

    def __str__(self):
        return self._touch()

    def __repr__(self):
        return self._touch()

    def __format__(self, spec):
        return self._touch()

    def __float__(self):
        return self._touch()

    def __int__(self):
        return self._touch()

    def __bool__(self):
        return self._touch()


class HostileSectionKey:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __hash__(self):
        return 0

    def __eq__(self, other):
        type(self).touched += 1
        raise RuntimeError("caller-owned PE key comparison executed")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned PE key repr executed")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned PE key str executed")


class HostileMapping:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def items(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned PE mapping items executed")

    def get(self, key, default=None):
        type(self).touched += 1
        raise RuntimeError("caller-owned PE mapping get executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned PE mapping iter executed")



def test_stage1699_pe_section_tags_reject_hostile_values_without_hooks():
    HostileSectionValue.reset()
    tags: list[str] = []

    binary_pe_surface._add_single_section_tags(
        tags,
        {
            "name": HostileSectionValue(),
            "entropy": HostileSectionValue(),
            "raw_size": HostileSectionValue(),
            "virtual_size": HostileSectionValue(),
        },
    )

    assert HostileSectionValue.touched == 0
    assert "pe_section_materialize_scan_error" in tags
    assert "binary_final_json_must_record" in tags
    assert "scanner_failure_evidence_recorded" in tags
    assert "scanner_failure_evidence:binary:pe_section_materialize" in tags
    assert not any(tag.startswith("pe_section_<") for tag in tags)



def test_stage1699_pe_section_tags_reject_hostile_keys_without_comparison_hooks():
    HostileSectionKey.reset()
    tags: list[str] = []

    binary_pe_surface._add_single_section_tags(
        tags,
        {
            HostileSectionKey(): ".text",
            "entropy": 8.0,
            "raw_size": 0,
            "virtual_size": 12,
        },
    )

    assert HostileSectionKey.touched == 0
    assert "pe_section_materialize_scan_error" in tags
    assert "scanner_failure_evidence:binary:pe_section_materialize" in tags
    assert "high_entropy_section" not in tags
    assert "virtual_only_section" not in tags



def test_stage1699_pe_section_tags_reject_mapping_like_objects_without_hooks():
    HostileMapping.reset()
    tags: list[str] = []

    binary_pe_surface._add_single_section_tags(tags, HostileMapping())

    assert HostileMapping.touched == 0
    assert "pe_section_materialize_scan_error" in tags
    assert "scanner_failure_evidence:binary:pe_section_materialize" in tags



def test_stage1699_pe_section_tags_preserve_exact_section_values():
    tags: list[str] = []

    binary_pe_surface._add_single_section_tags(
        tags,
        {"name": ".Odd Name", "entropy": 7.5, "raw_size": 0, "virtual_size": 12},
    )

    assert "pe_section_.odd_name" in tags
    assert "high_entropy_section" in tags
    assert "packed_or_obfuscated" in tags
    assert "virtual_only_section" in tags



def test_stage1699_pe_section_source_has_no_unsafe_section_materialization():
    source = Path(binary_pe_surface.__file__).read_text(encoding="utf-8")

    forbidden = (
        "section.get(",
        "str(section",
        "float(section",
        "int(section",
        "dict(section)",
    )
    for pattern in forbidden:
        assert pattern not in source
