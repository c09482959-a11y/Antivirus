"""Misc tag-to-behavior defaults."""
from __future__ import annotations

from Virus_Scan.detection.registries.immutability import freeze_registry_value

MISC_TAG_TO_BEHAVIOR = freeze_registry_value({'asset_resource_fetch': 'asset_resource_fetch',
 'clipboard_access': 'collection',
 'clipboard_crypto': 'collection',
 'confirmed_injection_chain': 'process_injection',
 'dll_hijack': 'dll_load',
 'dll_load': 'dll_load',
 'dll_sideload': 'dll_load',
 'file_access': 'file_access',
 'file_collection': 'collection',
 'game_resource_cache': 'game_resource_cache',
 'keylogging_behavior': 'collection',
 'memory_allocate': 'memory_allocate',
 'memory_protect': 'memory_protect',
 'memory_read': 'memory_read',
 'memory_write': 'memory_write',
 'process_hollowing': 'process_hollowing',
 'process_injection': 'process_injection',
 'screenshot_capture': 'collection',
 'thread_execution': 'thread_execution',
 'user_context': 'user_context',
 'write_process_memory': 'memory_write'})

__all__ = ("MISC_TAG_TO_BEHAVIOR",)
