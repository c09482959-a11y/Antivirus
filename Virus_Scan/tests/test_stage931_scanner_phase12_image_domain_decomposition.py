from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.scanners.image import (
    rewrite_stego_tags,
    scan_image_file,
    scan_image_stego,
)
from Virus_Scan.scanners.image_lsb import scan_pillow_lsb
from Virus_Scan.scanners.image_malformed import fast_image_sample_malformed_status
from Virus_Scan.scanners.image_png_chunks import scan_png_chunks



def test_image_public_surface_delegates_to_bounded_scanner_modules():
    assert callable(scan_image_file)
    assert callable(scan_image_stego)
    assert callable(rewrite_stego_tags)
    assert callable(scan_pillow_lsb)
    assert fast_image_sample_malformed_status("asset.png", b"not-png") == "malformed"


def test_image_png_metadata_no_longer_imports_core_logging_private_helper():
    image_source = read_python_file(Path("Virus_Scan/scanners/image.py"))
    stego_source = read_python_file(Path("Virus_Scan/scanners/image_stego.py"))
    assert "Virus_Scan.core.logging" not in image_source
    assert "Virus_Scan.core.logging" not in stego_source
    assert "Virus_Scan.scanners.image_png_chunks" in stego_source


class _BrokenPngBytes:
    def startswith(self, *_args, **_kwargs):
        raise TypeError("synthetic png probe failure")


def test_png_chunk_scanner_failure_is_explicit_image_evidence():
    tags = []
    suspicious = scan_png_chunks(_BrokenPngBytes(), tags)
    assert suspicious is True
    assert "image_metadata_parse_failed" in tags
    assert "malformed_image_input" in tags
    assert "scanner_failure_evidence_recorded" in tags
