"""Replayable decisions for raw queue identity projections."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_items_from_items
from dataclasses import dataclass
from pathlib import PosixPath, WindowsPath

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name

_EXACT_FILESYSTEM_PATH_TYPES = (PosixPath, WindowsPath)


@dataclass(frozen=True, slots=True)
class QueueIdentityMappingDecision:
    """Typed decision for raw queue identity mapping materialization."""

    accepted: bool
    reason: str
    value_type: str
    items: tuple[tuple[str, object], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "items", tuple(self.items))

    def as_mapping_or_none(self) -> dict[str, object] | None:
        """Return the canonical mapping/None projection for queue identity callers."""
        if not self.accepted:
            return None
        return dict(self.items)


@dataclass(frozen=True, slots=True)
class QueueIdentityIndexGetFailureDecision:
    """Typed decision for unavailable queue identity cache lookups."""

    accepted: bool
    reason: str
    queue_dir_type: str
    states_type: str
    error_type: str

    def as_value(self) -> None:
        """Return the canonical cache-miss projection for queue identity callers."""
        return


def queue_identity_mapping_decision(value: object) -> QueueIdentityMappingDecision:
    """Return a replayable no-hook decision for raw queue identity mappings."""
    items = no_hook_mapping_items(value, allow_dict_subclass=True)
    if items is None:
        return QueueIdentityMappingDecision(
            accepted=False,
            reason="queue_identity_mapping_unavailable" if value is None else "queue_identity_mapping_unsupported",
            value_type=no_hook_type_name(value),
        )
    return QueueIdentityMappingDecision(
        accepted=True,
        reason="queue_identity_mapping_accepted",
        value_type=no_hook_type_name(value),
        items=scheduler_str_key_items_from_items(items),
    )


def queue_identity_index_get_failure_decision(
    queue_dir: object,
    states: object,
    exc: BaseException,
) -> QueueIdentityIndexGetFailureDecision:
    """Return a replayable decision for queue identity index lookup failures."""
    queue_dir_type = "PosixPath" if type(queue_dir) in _EXACT_FILESYSTEM_PATH_TYPES else no_hook_type_name(queue_dir)
    return QueueIdentityIndexGetFailureDecision(
        accepted=False,
        reason="queue_identity_index_get_failed",
        queue_dir_type=queue_dir_type,
        states_type=no_hook_type_name(states),
        error_type=type(exc).__name__,
    )


__all__ = (
    "QueueIdentityIndexGetFailureDecision",
    "QueueIdentityMappingDecision",
    "queue_identity_index_get_failure_decision",
    "queue_identity_mapping_decision",
)
