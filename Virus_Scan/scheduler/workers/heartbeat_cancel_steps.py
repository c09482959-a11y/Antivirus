"""Bounded shared heartbeat cancellation read helpers."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scheduler.internal.owned_indexed_sequence import (
    is_owned_indexed_sequence,
    owned_indexed_get,
    owned_indexed_length,
)
from Virus_Scan.scheduler.workers.heartbeat_support import (
    HB_CANCEL_REQUEST,
    HB_FORCE_RETIRE,
    HB_POISONED,
    safe_heartbeat_int,
)

_CANCEL_FLAGS = HB_CANCEL_REQUEST | HB_FORCE_RETIRE | HB_POISONED
_CANCEL_NOT_REQUESTED = False


@dataclass(frozen=True)
class CancelIdentity:
    job_id: int
    generation: int


def cancel_identity(job_id: object, generation: object) -> CancelIdentity | str:
    jid, jid_reason = safe_heartbeat_int(
        job_id,
        rejection_reason="cancel_job_id_rejected",
        non_finite_reason="cancel_job_id_non_finite",
    )
    gen, gen_reason = safe_heartbeat_int(
        generation,
        rejection_reason="cancel_generation_rejected",
        non_finite_reason="cancel_generation_non_finite",
    )
    if jid_reason or gen_reason:
        return jid_reason or gen_reason
    return CancelIdentity(job_id=jid, generation=gen)


def cancel_flag_requested(stored_generation: int, generation: int, stored_flags: int) -> bool:
    if stored_generation != generation:
        return _CANCEL_NOT_REQUESTED
    return (stored_flags & _CANCEL_FLAGS) != 0


def validated_cancel_scalars(
    stored_generation: object,
    stored_flags: object,
) -> tuple[int, int]:
    parsed_generation, generation_reason = safe_heartbeat_int(
        stored_generation,
        rejection_reason="cancel_stored_generation_rejected",
        non_finite_reason="cancel_stored_generation_non_finite",
    )
    parsed_flags, flags_reason = safe_heartbeat_int(
        stored_flags,
        rejection_reason="cancel_flags_rejected",
        non_finite_reason="cancel_flags_non_finite",
    )
    if generation_reason or flags_reason:
        raise ValueError(generation_reason or flags_reason)
    return parsed_generation, parsed_flags


def array_cancel_requested(
    cancel_table: dict[object, object],
    identity: CancelIdentity,
) -> bool:
    gens = dict.get(cancel_table, "generation")
    flags = dict.get(cancel_table, "flags")
    if not is_owned_indexed_sequence(gens, writable=False):
        raise ValueError("cancel_shared_arrays_rejected")
    if not is_owned_indexed_sequence(flags, writable=False):
        raise ValueError("cancel_shared_arrays_rejected")
    if identity.job_id >= owned_indexed_length(gens):
        raise ValueError("cancel_job_id_out_of_range")
    if identity.job_id >= owned_indexed_length(flags):
        raise ValueError("cancel_job_id_out_of_range")
    stored_generation, stored_flags = validated_cancel_scalars(
        owned_indexed_get(gens, identity.job_id),
        owned_indexed_get(flags, identity.job_id),
    )
    return cancel_flag_requested(stored_generation, identity.generation, stored_flags)


def mapping_cancel_requested(
    cancel_table: dict[object, object],
    identity: CancelIdentity,
) -> bool:
    entry = dict.get(cancel_table, int.__str__(identity.job_id))
    if type(entry) is not dict:
        raise ValueError("cancel_entry_rejected")
    stored_generation, stored_flags = validated_cancel_scalars(
        dict.get(entry, "generation", 0),
        dict.get(entry, "flags", 0),
    )
    return cancel_flag_requested(stored_generation, identity.generation, stored_flags)


def heartbeat_cancel_requested(
    cancel_table: dict[object, object],
    identity: CancelIdentity,
) -> bool:
    gens = dict.get(cancel_table, "generation")
    flags = dict.get(cancel_table, "flags")
    if gens is not None or flags is not None:
        return array_cancel_requested(cancel_table, identity)
    return mapping_cancel_requested(cancel_table, identity)


__all__ = (
    "CancelIdentity",
    "cancel_identity",
    "heartbeat_cancel_requested",
)
