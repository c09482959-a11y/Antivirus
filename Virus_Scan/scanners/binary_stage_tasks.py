"""Binary scanner micro-stage task construction."""

from __future__ import annotations

from Virus_Scan.scanners.binary_pe import scan_pure_python_pe_file
from Virus_Scan.scanners.binary_micro_stage import micro_stage_collect as _micro_stage_collect

def _append_micro_binary_stage_tasks(binary_tasks: object, path: object, tags: object) -> object:
    """Build fine-grained binary raw micro-layers before central merge."""
    del tags  # Explicitly unused contract parameters.
    binary_tasks.append(('micro_identity_raw', _micro_stage_collect, ('file_identity', path), {}))
    binary_tasks.append(('micro_binary_context_raw', _micro_stage_collect, ('binary_context', path), {}))
    binary_tasks.append(('micro_binary_payload_raw', _micro_stage_collect, ('binary_payload', path), {}))
    binary_tasks.append(('micro_pickle_payload_raw', _micro_stage_collect, ('pickle_payload', path), {}))
    binary_tasks.append(('micro_pe_api_raw', _micro_stage_collect, ('pe_api', path), {}))
    binary_tasks.append(('micro_pure_pe_raw', scan_pure_python_pe_file, (path,), {'finalize': False, 'include_strings': False}))
    return binary_tasks

__all__ = ("_append_micro_binary_stage_tasks",)
