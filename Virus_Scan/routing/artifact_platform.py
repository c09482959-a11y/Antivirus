"""Canonical fail-closed artifact-platform classification.

This owner classifies only the platform represented by static artifact evidence.
It does not infer runtime execution, and it never consumes YARA rule identity or
ATT&CK alignment metadata.
"""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text
from Virus_Scan.routing.magic import sniff_file_identity
from Virus_Scan.routing.extension_outcome import route_identity_record

ARTIFACT_PLATFORMS = frozenset({"windows", "linux", "macos"})

_WINDOWS_MAGIC_TYPES = frozenset({"pe_mz", "mono_dotnet_assembly"})
_LINUX_MAGIC_TYPES = frozenset({"elf"})
_MACOS_MAGIC_TYPES = frozenset({"macho"})

_WINDOWS_STATIC_MARKERS = (
    "powershell",
    "encodedcommand",
    "frombase64string",
    "writeprocessmemory",
    "virtualallocex",
    "createremotethread",
    "ntcreatethreadex",
    "minidumpwritedump",
    "lsass.exe",
    "kernel32.dll",
    "advapi32.dll",
    "ntdll.dll",
)
_LINUX_STATIC_MARKERS = (
    "/bin/sh",
    "/bin/bash",
    "systemctl ",
    "systemd",
    "proc/self/",
)
_MACOS_STATIC_MARKERS = (
    "/applications/",
    "launchagents",
    "launchdaemons",
    "osascript",
    "objective-c",
)


def _artifact_platform_text(value: object) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="artifact_platform_text_missing",
        unsupported_reason="artifact_platform_text_rejected",
    )
    return "" if reason else text.strip().casefold()


def _identity_magic_type(router_identity: object) -> str:
    identity = route_identity_record(router_identity)
    if identity is None:
        return ""
    return _artifact_platform_text(dict.get(identity, "magic_type"))


def artifact_platform_from_router_identity(router_identity: object) -> str:
    """Return a platform only for an unambiguous canonical magic identity."""
    magic_type = _identity_magic_type(router_identity)
    if magic_type in _WINDOWS_MAGIC_TYPES:
        return "windows"
    if magic_type in _LINUX_MAGIC_TYPES:
        return "linux"
    if magic_type in _MACOS_MAGIC_TYPES:
        return "macos"
    return ""


def artifact_platform_from_static_text(strings_blob: object) -> str:
    """Return one platform represented by exact static artifact markers."""
    text = _artifact_platform_text(strings_blob)
    if not text:
        return ""
    candidates: set[str] = set()
    if any(marker in text for marker in _WINDOWS_STATIC_MARKERS):
        candidates.add("windows")
    if any(marker in text for marker in _LINUX_STATIC_MARKERS):
        candidates.add("linux")
    if any(marker in text for marker in _MACOS_STATIC_MARKERS):
        candidates.add("macos")
    return next(iter(candidates)) if len(candidates) == 1 else ""


def canonical_artifact_platform(
    path: object,
    *,
    router_identity: object = None,
    strings_blob: object = "",
) -> str:
    """Resolve one artifact platform from canonical routing and static evidence.

    Conflicting evidence fails closed.  When a router identity is unavailable,
    the existing canonical magic owner is invoked once for this classification.
    """
    route_identity = route_identity_record(router_identity)
    identity_platform = artifact_platform_from_router_identity(route_identity)
    if route_identity is None:
        identity_platform = artifact_platform_from_router_identity(sniff_file_identity(path))
    text_platform = artifact_platform_from_static_text(strings_blob)
    candidates = {item for item in (identity_platform, text_platform) if item}
    return next(iter(candidates)) if len(candidates) == 1 else ""


__all__ = (
    "ARTIFACT_PLATFORMS",
    "artifact_platform_from_router_identity",
    "artifact_platform_from_static_text",
    "canonical_artifact_platform",
)
