"""Owned process-environment publication for UMIGE runtime configuration.

Batch 2 bootstrap ownership rule: runtime configuration may read environment while
being assembled, but all writes back to ``os.environ`` are performed by this
single owner.  Scheduler/scanner modules consume selected
UMIGE_* values from the process environment, so this owner preserves that
interface while making mutation order explicit, auditable, and snapshot-backed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping
import os

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_text,
)
from Virus_Scan.runtime.structured_failures import record_suppressed_failure

_WORKER_SHARED_PERSISTENCE_WRITE_DISABLED_FLAGS = ("UMIGE_PROCESS_SHARD", "UMIGE_PROCESS_QUEUE", "UMIGE_INMEMORY_WORKER")


def _environment_search_terms() -> list[str]:
    snapshot = os.environ.copy()
    terms: list[str] = []
    for key, value in dict.items(snapshot):
        if type(key) is str:
            terms.append(str.__str__(key).lower())
        if type(value) is str:
            terms.append(str.__str__(value).lower())
    return terms


@dataclass
class RuntimeEnvironmentOwner:
    """Single writer for process-environment values owned by the scan runtime."""

    published: dict[str, str] = field(default_factory=dict)

    def publish(self, values: Mapping[str, object], *, overwrite: bool = True) -> dict[str, str]:
        """Publish validated environment values and return the values written.

        Only string keys beginning with ``UMIGE_`` are accepted.  ``None`` values
        are ignored so callers can pass optional configuration without creating
        ambiguous empty variables.  The method intentionally does not catch
        assignment errors; environment publication is a startup/configuration
        boundary and failures must remain visible.
        """
        items = no_hook_mapping_items(values)
        if items is None:
            raise ValueError("runtime_environment_mapping_rejected")
        prepared: list[tuple[str, str]] = []
        for key, value in items:
            if value is None:
                continue
            if type(key) is not str or not str.__str__(key).startswith("UMIGE_"):
                raise ValueError("invalid_runtime_environment_key")
            text, reason = no_hook_text(
                value,
                missing_reason="runtime_environment_value_missing",
                unsupported_reason="runtime_environment_value_rejected",
            )
            if reason:
                raise ValueError(reason)
            prepared.append((str.__str__(key), text))
        written: dict[str, str] = {}
        for key, text in prepared:
            if overwrite or key not in os.environ:
                os.environ[key] = text
                written[key] = text
                self.published[key] = text
        return written

    def publish_defaults(self, values: Mapping[str, object]) -> dict[str, str]:
        """Publish values only where the process environment has no preexisting value."""
        return self.publish(values, overwrite=False)

    def snapshot(self, prefix: str = "UMIGE_") -> dict[str, str]:
        """Return a deterministic snapshot of owned environment values."""
        return {k: os.environ[k] for k in sorted(os.environ) if k.startswith(prefix)}

    def bool_flag(self, name: str, *, default: bool = False) -> bool:
        if type(name) is not str:
            raise ValueError("runtime_environment_flag_name_rejected")
        default_text = "1" if default else "0"
        raw_value = os.environ.get(str.__str__(name), default_text)
        value = raw_value.strip().lower() if type(raw_value) is str else default_text
        return value not in {"0", "false", "no", "off"}

    def any_bool_flag(self, names: tuple[str, ...], *, default: bool = False) -> bool:
        values = no_hook_sequence_items(names) if type(names) in (tuple, list) else ()
        return any(self.bool_flag(name, default=default) for name in values)

    def contains_text(self, *needles: str) -> bool:
        cleaned: list[str] = []
        for needle in needles:
            text, reason = no_hook_text(
                needle,
                missing_reason="runtime_environment_needle_missing",
                unsupported_reason="runtime_environment_needle_rejected",
            )
            text = text.strip().lower()
            if not reason and text:
                cleaned.append(text)
        if not cleaned:
            return False
        joined = " ".join(_environment_search_terms())
        return any(needle in joined for needle in cleaned)

    def is_process_shard(self) -> bool:
        return self.bool_flag("UMIGE_PROCESS_SHARD")

def runtime_worker_shared_persistence_writes_disabled(env: Mapping[str, object] | None = None) -> bool:
    """Return True when the current process must not write shared persistence state.

    Runtime owns this process-environment identity check because it describes
    process bootstrap context. Scheduler, models, and shared persistence consumers use
    this runtime-owned policy instead of each owning scheduler-specific reads.
    """
    if env is None:
        items = tuple((name, os.environ.get(name, "0")) for name in _WORKER_SHARED_PERSISTENCE_WRITE_DISABLED_FLAGS)
    else:
        source_items = no_hook_mapping_items(env)
        if source_items is None:
            record_suppressed_failure(
                "runtime_worker_shared_persistence_environment_rejected",
                ValueError("runtime_worker_shared_persistence_environment_rejected"),
                domain="runtime_environment",
            )
            return True
        source = dict(source_items)
        items = tuple((name, dict.get(source, name, "0")) for name in _WORKER_SHARED_PERSISTENCE_WRITE_DISABLED_FLAGS)
    for name, raw_value in items:
        value, reason = no_hook_text(
            raw_value,
            missing_reason="runtime_worker_shared_persistence_flag_missing",
            unsupported_reason="runtime_worker_shared_persistence_flag_rejected",
        )
        if reason:
            record_suppressed_failure(
                "runtime_worker_shared_persistence_flag_rejected",
                ValueError(reason),
                domain="runtime_environment",
                context={"name": name},
            )
            return True
        if value.strip().lower() not in {"0", "false", "no", "off", ""}:
            return True
    return False
