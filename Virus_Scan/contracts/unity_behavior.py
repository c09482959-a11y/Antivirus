"""Neutral Unity behavior semantic contract.

This module owns deterministic Unity runtime-marker projection for callers that
need Unity semantic tags without importing scanner/runtime dependency ports.
"""
from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.contracts.no_hook_materialization import no_hook_text

UNITY_LIFECYCLE_HOOKS = ("Awake", "Start", "Update", "FixedUpdate", "OnEnable", "OnDisable")
UNITY_RUNTIME_CHECKS = MappingProxyType({
    "AddComponent": "unity_dynamic_component",
    "GameObject.Find": "unity_scene_manipulation",
    "StartCoroutine": "unity_async_flow",
    "AssetBundle": "unity_asset_loading",
    "Resources.Load": "unity_resource_load",
    "Assembly.Load": "assembly_load",
    "BinaryFormatter": "binary_deserialize",
    "Process.Start": "process_exec",
    "WebClient": "network_download",
    "DownloadString": "network_download",
    "DownloadData": "network_download",
    "VirtualAlloc": "memory_allocation_api",
    "CreateRemoteThread": "remote_thread_api",
    "DllImport": "native_interop",
})


def detect_unity_runtime_behavior(text: object) -> tuple[str, ...]:
    """Return deterministic Unity runtime behavior tags for text-like input."""
    tags: set[str] = set()
    value, reason = no_hook_text(text, missing_reason="missing_unity_text", unsupported_reason="unsafe_unity_text_rejected")
    if reason:
        return ()
    for hook in UNITY_LIFECYCLE_HOOKS:
        if "void " + hook in value or hook + "(" in value:
            tags.add("unity_lifecycle")
    for needle, tag in tuple(UNITY_RUNTIME_CHECKS.items()):
        if needle in value:
            tags.add(tag)
    return tuple(sorted(tags))


__all__ = ("UNITY_LIFECYCLE_HOOKS", "UNITY_RUNTIME_CHECKS", "detect_unity_runtime_behavior")
