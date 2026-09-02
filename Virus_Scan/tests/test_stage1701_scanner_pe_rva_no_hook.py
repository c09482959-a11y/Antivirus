"""Stage1701 PE RVA section mapping no-hook regressions."""
from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.scanners import binary_pe_bytes


class HostileSectionSequence:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned section sequence bool executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned section sequence iter executed")


class HostileSectionMapping:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def get(self, key, default=None):
        type(self).touched += 1
        raise RuntimeError("caller-owned section get executed")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned section items executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned section iter executed")


class HostileSectionInteger:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned section int executed")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned section bool executed")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned section repr executed")


class HostileSectionKey:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __hash__(self):
        return 0

    def __eq__(self, other):
        type(self).touched += 1
        raise RuntimeError("caller-owned section key eq executed")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned section key repr executed")



def test_stage1701_pe_rva_rejects_hostile_section_sequence_without_hooks():
    HostileSectionSequence.reset()

    with pytest.raises(ValueError, match="section sequence rejected"):
        binary_pe_bytes.pe_rva_to_offset(1, HostileSectionSequence())

    assert HostileSectionSequence.touched == 0



def test_stage1701_pe_rva_rejects_hostile_section_mapping_without_hooks():
    HostileSectionMapping.reset()

    with pytest.raises(ValueError, match="section mapping rejected"):
        binary_pe_bytes.pe_rva_to_offset(1, (HostileSectionMapping(),))

    assert HostileSectionMapping.touched == 0



def test_stage1701_pe_rva_rejects_hostile_section_integer_without_hooks():
    HostileSectionInteger.reset()

    with pytest.raises(ValueError, match="section integer rejected"):
        binary_pe_bytes.pe_rva_to_offset(
            0x1010,
            (
                {
                    "virtual_address": HostileSectionInteger(),
                    "virtual_size": 0x100,
                    "raw_size": 0x80,
                    "raw_ptr": 0x200,
                },
            ),
        )

    assert HostileSectionInteger.touched == 0



def test_stage1701_pe_rva_rejects_hostile_section_key_without_hooks():
    HostileSectionKey.reset()

    with pytest.raises(ValueError, match="section key rejected"):
        binary_pe_bytes.pe_rva_to_offset(
            0x1010,
            (
                {
                    HostileSectionKey(): 0,
                    "virtual_address": 0x1000,
                    "virtual_size": 0x100,
                    "raw_size": 0x80,
                    "raw_ptr": 0x200,
                },
            ),
        )

    assert HostileSectionKey.touched == 0



def test_stage1701_pe_rva_preserves_exact_owned_section_mapping():
    sections = (
        {
            "virtual_address": 0x1000,
            "virtual_size": 0x100,
            "raw_size": 0x80,
            "raw_ptr": 0x200,
        },
    )

    assert binary_pe_bytes.pe_rva_to_offset(0x1010, sections) == 0x210
    assert binary_pe_bytes.pe_rva_to_offset(0x2000, sections) is None



def test_stage1701_pe_rva_source_has_no_unsafe_section_conversions():
    source = Path(binary_pe_bytes.__file__).read_text(encoding="utf-8")

    forbidden = (
        "sections or",
        ".get(",
        "int(section.get",
        "int(rva)",
    )
    for pattern in forbidden:
        assert pattern not in source
