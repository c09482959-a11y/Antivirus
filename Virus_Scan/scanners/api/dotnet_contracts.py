"""Public .NET scanner contracts."""
from Virus_Scan.scanners.dotnet import scan_unity_dotnet_layered_file, scan_unity_ilspy_file, unity_ilspy_should_run
from Virus_Scan.scanners.dotnet_identity import DOTNET_BEHAVIOR_MARKERS, DOTNET_EXTENSIONS, DOTNET_METADATA_MARKERS, dotnet_behavior_tags, dotnet_extension_tags, dotnet_metadata_present
__all__ = ("DOTNET_BEHAVIOR_MARKERS", "DOTNET_EXTENSIONS", "DOTNET_METADATA_MARKERS", "dotnet_behavior_tags", "dotnet_extension_tags", "dotnet_metadata_present", "scan_unity_dotnet_layered_file", "scan_unity_ilspy_file", "unity_ilspy_should_run")
