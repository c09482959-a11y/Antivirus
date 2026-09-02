from pathlib import Path

import Virus_Scan.routing.magic as magic
from Virus_Scan.routing.magic import (
    MagicRouter,
    claimed_filetype_category,
    expected_magic_mismatch,
    sniff_file_identity,
)


def test_routing_magic_records_png_identity(tmp_path: Path) -> None:
    sample = tmp_path / "title.png"
    sample.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 64)

    identity = sniff_file_identity(sample)

    assert identity["ext"] == ".png"
    assert identity["magic_stage"] == "image"
    assert identity["magic_type"] == "png"
    assert "magic_png" in identity["tags"]
    assert "extension_consistent" in identity["tags"]


def test_routing_magic_records_mislabeled_pe_as_extension_mismatch(tmp_path: Path) -> None:
    sample = tmp_path / "fake.png"
    sample.write_bytes(b"MZ" + b"\x00" * 64)

    identity = sniff_file_identity(sample)

    assert identity["ext"] == ".png"
    assert identity["magic_stage"] == "binary"
    assert identity["magic_type"] == "pe_mz"
    assert "extension_mismatch" in identity["tags"]
    assert "actual_stage_binary" in identity["tags"]
    assert "claimed_stage_image" in identity["tags"]


def test_stage1073_routing_magic_exports_public_filetype_contracts() -> None:
    assert "expected_magic_mismatch" in magic.__all__
    assert "claimed_filetype_category" in magic.__all__
    assert "_expected_magic_mismatch" not in magic.__all__
    assert "_claimed_filetype_category" not in magic.__all__
    assert not hasattr(magic, "_expected_magic_mismatch")
    assert not hasattr(magic, "_claimed_filetype_category")
    assert expected_magic_mismatch is magic.expected_magic_mismatch
    assert claimed_filetype_category is magic.claimed_filetype_category


def test_stage1073_routing_magic_public_contracts_preserve_behavior() -> None:
    assert expected_magic_mismatch(".png", "pe_mz") is True
    assert expected_magic_mismatch(".png", "png") is False
    assert claimed_filetype_category(".png") == "image"
    assert MagicRouter.expected_magic_mismatch(".png", "pe_mz") is True
    assert MagicRouter.claimed_filetype_category(".png") == "image"
