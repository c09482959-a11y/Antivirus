"""Canonical route-identity provenance carried across in-memory worker IPC."""
from __future__ import annotations

from Virus_Scan.routing.extension_outcome import route_identity_record

INMEMORY_ROUTE_IDENTITY_FIELD = "_inmemory_route_identity"


def attach_inmemory_route_identity(
    record: dict[str, object],
    router_identity: object,
) -> dict[str, object]:
    """Attach one exact router identity record for parent-side publication."""
    if type(record) is not dict:
        raise TypeError("inmemory_route_identity_result_record_invalid")
    identity = route_identity_record(router_identity)
    if identity is not None:
        record[INMEMORY_ROUTE_IDENTITY_FIELD] = identity
    return record


def consume_inmemory_route_identity(record: dict[str, object]) -> dict[str, object] | None:
    """Remove and return the exact worker-owned router identity record."""
    if type(record) is not dict:
        raise TypeError("inmemory_route_identity_result_record_invalid")
    raw_identity = dict.pop(record, INMEMORY_ROUTE_IDENTITY_FIELD, None)
    return route_identity_record(raw_identity)


__all__ = (
    "INMEMORY_ROUTE_IDENTITY_FIELD",
    "attach_inmemory_route_identity",
    "consume_inmemory_route_identity",
)
