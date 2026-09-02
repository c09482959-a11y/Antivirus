from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file, read_python_file


import ast
from pathlib import Path

from PIL import Image

from Virus_Scan.scanners.image_lsb import extract_lsb_payload_gated
from Virus_Scan.scanners.image_lsb_payload import (
    decoded_lsb_payload_behavior_tags,
    has_lsb_trigger_tags,
    lsb_payload_magic_or_needle_hit,
)


def _payload_bits(payload: bytes) -> list[int]:
    bits: list[int] = []
    for byte in payload:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def _write_lsb_image(path: Path, payload: bytes) -> None:
    bits = _payload_bits(payload)
    values = []
    for index in range(24 * 24 * 3):
        bit = bits[index] if index < len(bits) else 0
        values.append(254 | bit)
    pixels = [tuple(values[i : i + 3]) for i in range(0, len(values), 3)]
    img = Image.new("RGB", (24, 24))
    img.putdata(pixels)
    img.save(path)


def test_image_lsb_payload_classification_is_owned_by_bounded_payload_module():
    image_lsb_source = read_python_file(Path("Virus_Scan/scanners/image_lsb.py"))
    payload_source = read_python_file(Path("Virus_Scan/scanners/image_lsb_payload.py"))

    assert len(image_lsb_source.splitlines()) <= 200
    assert "Virus_Scan.scanners.payload_decode" not in image_lsb_source
    assert "Virus_Scan.scanners.image_lsb_payload" in image_lsb_source
    assert "Virus_Scan.scanners.payload_decode" in payload_source


def test_image_lsb_payload_module_has_no_image_traversal_or_private_runtime_imports():
    tree = parse_python_file(Path("Virus_Scan/scanners/image_lsb_payload.py"))
    imports = []
    loops = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)
        elif isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            loops.append(node)

    assert "PIL" not in imports
    assert "Virus_Scan.core.logging" not in imports
    assert not any(module.startswith("Virus_Scan.runtime") for module in imports)
    assert not any(
        isinstance(loop.iter, ast.Call) and getattr(loop.iter.func, "attr", "") == "getdata"
        for loop in loops
    )


def test_lsb_payload_helpers_preserve_magic_and_trigger_behavior():
    tags = ["stego_statistical_anomaly"]
    assert has_lsb_trigger_tags(tags) is True
    assert lsb_payload_magic_or_needle_hit(b"MZ" + b"\0" * 128) is True
    assert decoded_lsb_payload_behavior_tags(b"plain benign text" + b"\0" * 80) == []


def test_gated_lsb_extraction_still_records_confirmed_payload(tmp_path):
    image_path = tmp_path / "payload.png"
    _write_lsb_image(image_path, b"MZ" + b"\0" * 96)
    tags = ["stego_statistical_anomaly"]

    suspicious = extract_lsb_payload_gated(image_path, tags)

    assert suspicious is True
    assert "image_payload_confirmed" in tags
    assert "image_lsb_payload_extracted" in tags
    assert "stego_payload_extracted" in tags
    assert "evidence_link:stego_payload_to_content" in tags
