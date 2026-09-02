"""Canonical detached, retention-bounded engine-profile persistence snapshot."""
from __future__ import annotations

import json

from Virus_Scan.models.api.profile_retention_contracts import (
    prune_engine_profile_for_retention,
    prune_staged_benign_store,
)
from Virus_Scan.models.profiles.schema import (
    ProfileSchemaInvariantError,
    validate_engine_profile_schema,
)
from Virus_Scan.models.profiles.staged_store_schema import (
    validate_staged_benign_store,
)


def persisted_engine_profile_snapshot(
    profile: object, *, expected_engine: str,
) -> dict[str, object]:
    """Detach, validate, retention-prune, and revalidate one profile snapshot."""
    try:
        encoded = json.dumps(
            profile, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        )
        detached = json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise ProfileSchemaInvariantError(
            expected_engine + ": profile is not canonical JSON",
        ) from exc
    if type(detached) is not dict:
        raise ProfileSchemaInvariantError(
            expected_engine + ": profile must be an object",
        )
    validate_engine_profile_schema(detached, expected_engine=expected_engine)
    retained = prune_engine_profile_for_retention(detached)
    if type(retained) is not dict:
        raise ProfileSchemaInvariantError(
            expected_engine + ": retained profile must be an object",
        )
    validate_engine_profile_schema(retained, expected_engine=expected_engine)
    return retained


def persisted_staged_benign_snapshot(store: object) -> dict[str, object]:
    """Detach, validate, retention-prune, and revalidate staged state."""
    try:
        detached = json.loads(json.dumps(
            store, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ))
    except (TypeError, ValueError) as exc:
        raise ValueError("staged benign store is not canonical JSON") from exc
    validate_staged_benign_store(detached)
    retained = prune_staged_benign_store(detached)
    validate_staged_benign_store(retained)
    return retained


__all__ = (
    "persisted_engine_profile_snapshot",
    "persisted_staged_benign_snapshot",
)
