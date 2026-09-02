"""Persistence tag-to-behavior defaults."""
from __future__ import annotations

from Virus_Scan.detection.registries.immutability import freeze_registry_value

PERSISTENCE_TAG_TO_BEHAVIOR = freeze_registry_value({'background_transfer': 'background_transfer',
 'execution_persistence': 'scheduled_task',
 'new_job': 'scheduled_task',
 'reg_exec': 'registry_mod',
 'registry_mod': 'registry_mod',
 'remote_registry': 'lateral_movement',
 'remote_scheduled_task': 'lateral_movement',
 'run_key_mod': 'registry_mod',
 'scheduled_execution': 'scheduled_task',
 'scheduled_task': 'scheduled_task',
 'schtasks_create': 'scheduled_task',
 'set_item_property': 'registry_mod',
 'startup_persistence': 'scheduled_task'})

__all__ = ("PERSISTENCE_TAG_TO_BEHAVIOR",)
