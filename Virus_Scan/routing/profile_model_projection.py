"""Routing-owned profile model projection boundary.

Routing owns engine selection and profile routing decisions.  Profile model
modules own schema validation, default profile construction, and profile loads.
This module is the narrow boundary that lets routing consume those model-owned
profile records without importing profile internals from routing decision files.
"""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import materialize_json_no_hook
from Virus_Scan.models.api.profile_contracts import (
    ProfileSchemaInvariantError,
    default_engine_profile,
    load_engine_profile,
)


def _routing_profile_copy(value: object) -> object:
    """Return a detached routing-owned JSON-safe profile projection.

    Routing consumes model-owned profile contracts but must not retain model
    mutable state or call caller-owned mapping/iteration/string hooks while
    detaching those contracts. The canonical no-hook materializer accepts exact
    builtin containers and owned mapping proxies and records explicit evidence
    for unsupported/hostile values.
    """
    return materialize_json_no_hook(value, context="routing_profile")


def default_routing_engine_profile(engine: str) -> Mapping[str, object]:
    """Return a detached default profile used for routing bootstrap."""
    return _routing_profile_copy(default_engine_profile(engine))


def load_routing_engine_profile(engine: str) -> Mapping[str, object]:
    """Load a detached engine profile for routing/scoring decisions."""
    return _routing_profile_copy(load_engine_profile(engine))


__all__ = (
    "ProfileSchemaInvariantError",
    "default_routing_engine_profile",
    "load_routing_engine_profile",
)
