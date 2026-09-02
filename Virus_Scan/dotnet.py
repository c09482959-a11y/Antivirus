"""Canonical package-level .NET scanner entrypoint for static runtime ownership."""
from __future__ import annotations

from Virus_Scan.scanners.api.dotnet_contracts import (
    DOTNET_BEHAVIOR_MARKERS,
    DOTNET_EXTENSIONS,
    DOTNET_METADATA_MARKERS,
    dotnet_behavior_tags,
    dotnet_extension_tags,
    dotnet_metadata_present,
    scan_unity_dotnet_layered_file,
    unity_ilspy_should_run,
)

__all__ = (
    "DOTNET_BEHAVIOR_MARKERS",
    "DOTNET_EXTENSIONS",
    "DOTNET_METADATA_MARKERS",
    "dotnet_behavior_tags",
    "dotnet_extension_tags",
    "dotnet_metadata_present",
    "scan_unity_dotnet_layered_file",
    "unity_ilspy_should_run",
)
