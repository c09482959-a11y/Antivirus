"""Scanner-owned public image scanner surface.

Implementation is decomposed into bounded image-domain modules: limits, malformed
magic probes, tag normalization, PNG/JPEG metadata, LSB extraction, stego
orchestration, and public scan entrypoint. This module preserves the historical
scanner public surface while avoiding mixed image/metadata/payload ownership.
"""
from __future__ import annotations

from Virus_Scan.scanners.image_scan import scan_image_file
from Virus_Scan.scanners.image_stego import scan_image_stego
from Virus_Scan.scanners.image_tags import rewrite_stego_tags


__all__ = (
    "rewrite_stego_tags",
    "scan_image_file",
    "scan_image_stego",
)
