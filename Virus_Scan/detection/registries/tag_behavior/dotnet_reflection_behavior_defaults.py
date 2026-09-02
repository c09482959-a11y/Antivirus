"""Dotnet Reflection tag-to-behavior defaults."""
from __future__ import annotations

from Virus_Scan.detection.registries.immutability import freeze_registry_value

DOTNET_REFLECTION_TAG_TO_BEHAVIOR = freeze_registry_value({'activator_createinstance': 'reflection',
 'assembly_load': 'assembly_load',
 'assembly_load_bytes': 'assembly_load',
 'assembly_loadfile': 'assembly_load',
 'assembly_loadfrom': 'assembly_load',
 'binary_deserialize': 'binary_deserialize',
 'binaryformatter_deserialize': 'binary_deserialize',
 'dynamic_method': 'dynamic_method',
 'emit_calli': 'dynamic_method',
 'load_from_bytes': 'assembly_load',
 'methodinfo_invoke': 'reflection',
 'reflection': 'reflection',
 'reflection_dotnet': 'reflection',
 'reflection_invoke': 'reflection'})

__all__ = ("DOTNET_REFLECTION_TAG_TO_BEHAVIOR",)
