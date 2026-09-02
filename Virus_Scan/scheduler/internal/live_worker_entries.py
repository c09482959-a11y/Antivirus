"""Live process-queue worker entry freezing.

Live scheduler carrier records must preserve owned process handles so timeout and
exit owners can terminate/wait on workers.  Only command payloads are recursively
frozen; unsupported entry shapes are made explicit without stringifying or
iterating caller-owned objects.
"""
from __future__ import annotations


from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence


_LIVE_WORKER_ENTRY_MIN_FIELDS = 3
_LIVE_WORKER_ENTRY_COMMAND_FIELDS = 4


def freeze_live_worker_entries(entries: object) -> tuple[tuple[object, object, object, tuple[object, ...]], ...]:
    """Freeze live worker entries while preserving owned process handles.

    Accepted entries are exact list/tuple values with at least ``idx, proc,
    output`` and optionally command.  The process handle and output path stay
    live-owned objects; command data is immutable and unsupported entry shapes
    become explicit scheduler evidence records.
    """
    if type(entries) not in {list, tuple}:
        return ((0, unsupported_scheduler_value_evidence(entries, field_name="worker_entries"), None, ()),)
    frozen: list[tuple[object, object, object, tuple[object, ...]]] = []
    for position, entry in enumerate(entries):
        if type(entry) in {list, tuple} and len(entry) >= _LIVE_WORKER_ENTRY_MIN_FIELDS:
            command = entry[3] if len(entry) >= _LIVE_WORKER_ENTRY_COMMAND_FIELDS else ()
            frozen.append((entry[0], entry[1], entry[2], immutable_tuple(command)))
            continue
        frozen.append((position, unsupported_scheduler_value_evidence(entry, field_name="worker_entry"), None, ()))
    return tuple(frozen)


__all__ = ("freeze_live_worker_entries",)
