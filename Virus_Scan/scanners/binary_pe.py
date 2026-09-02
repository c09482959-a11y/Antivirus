"""Scanner-owned PE/.NET binary public contracts.

This bounded module exports PE header, section/import, .NET metadata, and pure
Python PE surface scanning contracts while implementation ownership is split
into focused scanner-owned PE modules.
"""
from __future__ import annotations

from Virus_Scan.scanners.binary_pe_dotnet import dotnet_pe_result as _dotnet_pe_result, extract_dotnet_metadata, is_dotnet_pe
from Virus_Scan.scanners.binary_pe_headers import global_raw_pure_pe_header
from Virus_Scan.scanners.binary_pe_sections import (
    PEImportParseResult,
    PESectionParseResult,
    parse_pe_import_names as _umige_parse_pe_import_names,
    parse_pe_sections as _umige_parse_pe_sections,
)
from Virus_Scan.scanners.binary_pe_surface import scan_pure_python_pe_file

__all__ = (
    "PEImportParseResult",
    "PESectionParseResult",
    "_dotnet_pe_result",
    "_umige_parse_pe_import_names",
    "_umige_parse_pe_sections",
    "extract_dotnet_metadata",
    "global_raw_pure_pe_header",
    "is_dotnet_pe",
    "scan_pure_python_pe_file",
)
