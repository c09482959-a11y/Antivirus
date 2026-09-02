"""Deterministic runtime helpers for reproducible scan/replay audits."""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Iterable, Mapping, NoReturn

from Virus_Scan.contracts.no_hook_materialization import (
    exact_text_or_none,
    materialize_json_no_hook,
    no_hook_duplicate_key,
    no_hook_failure,
    no_hook_json_key,
    no_hook_json_sort_key,
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_text,
    no_hook_type_name,
)
from Virus_Scan.contracts.path_identity import should_include_scan_path


GOVERNANCE_SNAPSHOT_OWNER_REJECTED = "governance snapshot owner rejected"


def _raise_governance_snapshot_owner_rejected() -> NoReturn:
    raise TypeError(GOVERNANCE_SNAPSHOT_OWNER_REJECTED)


VOLATILE_RESULT_KEYS = frozenset({
    "time", "timestamp", "created_at", "updated_at", "worker_pid", "pid",
    "claim", "claim_path", "active_claim", "queue_claim", "duration",
    "duration_seconds", "elapsed", "elapsed_file", "started_at", "finished_at",
    "last_seen", "worker_id", "process_id",
})


def _determinism_text(*parts: str) -> str:
    return "".join(parts)


def _determinism_reason(*parts: str) -> str:
    return _determinism_text(*parts)


def _determinism_key_prefix(context: str) -> str:
    return _determinism_text(context, "_key")


def _determinism_ordered_dict_items(value: dict[str, object]) -> tuple[tuple[str, object], ...]:
    items = tuple(dict.items(value))
    return tuple(sorted(items, key=lambda row: row[0].casefold()))


def _determinism_result_error(prefix: str, key_text: str, suffix: str = "") -> str:
    return _determinism_text(prefix, key_text, suffix)


def _path_sort_key(value: object) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_runtime_path_key",
        unsupported_reason="unsafe_runtime_path_key_rejected",
    )
    if reason:
        return _determinism_text("~", reason, ":", no_hook_type_name(value))
    return text.replace("\\", "/").lower()


def _mapping_to_ordered_dict(value: object, *, context: str) -> dict[str, object]:
    items = no_hook_mapping_items(value)
    if items is None:
        return no_hook_failure(_determinism_reason("non_materializable_", context, "_mapping"), value)
    out: dict[str, object] = {}
    keyed: list[tuple[str, int, object, str, object]] = []
    for index, (key, item) in enumerate(items):
        key_text, key_reason = no_hook_json_key(key, index, prefix=_determinism_key_prefix(context))
        keyed.append((key_text, index, item, key_reason, key))
    for key_text, index, item, key_reason, key in sorted(keyed, key=lambda row: (row[0].casefold(), row[1])):
        if key_reason == "" and key_text.lower() in VOLATILE_RESULT_KEYS:
            continue
        output_key = no_hook_duplicate_key(key_text, index) if key_text in out else key_text
        if key_reason:
            out[output_key] = no_hook_failure(key_reason, key)
        else:
            out[output_key] = canonicalize_evidence_record(item)
    return out


def _immutable_json_value(value: object) -> object:
    """Return a recursively immutable JSON-comparable value.

    This is the canonical ownership boundary for governance snapshots. Frozen
    dataclasses alone do not protect nested dict/list payloads; this routine
    reconstructs mappings as mapping proxies and sequences as tuples so callers
    cannot mutate runtime snapshot state after capture.
    """
    safe = canonicalize_evidence_record(value)
    if type(safe) is dict:
        return MappingProxyType({
            key: _immutable_json_value(item)
            for key, item in _determinism_ordered_dict_items(safe)
        })
    if type(safe) is list:
        return tuple(_immutable_json_value(item) for item in safe)
    return safe


def _mutable_json_value(value: object) -> object:
    items = no_hook_mapping_items(value)
    if items is not None:
        out: dict[str, object] = {}
        for index, (key, item) in enumerate(sorted(items, key=lambda row: _path_sort_key(row[0]))):
            key_text, key_reason = no_hook_json_key(key, index, prefix="runtime_snapshot_key")
            if key_text in out:
                key_text = no_hook_duplicate_key(key_text, index)
            out[key_text] = no_hook_failure(key_reason, key) if key_reason else _mutable_json_value(item)
        return out
    if type(value) is tuple:
        return [_mutable_json_value(item) for item in value]
    if type(value) is list:
        return [_mutable_json_value(item) for item in value]
    return materialize_json_no_hook(value, context="runtime_snapshot")


@dataclass(frozen=True, slots=True)
class GovernanceSnapshot:
    queue_state: Mapping[str, object] = field(default_factory=lambda: MappingProxyType({}))
    quota_state: Mapping[str, object] = field(default_factory=lambda: MappingProxyType({}))
    replay_state: Mapping[str, object] = field(default_factory=lambda: MappingProxyType({}))
    scheduler_decisions: tuple[object, ...] = ()
    created_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if type(self) is not GovernanceSnapshot:
            _raise_governance_snapshot_owner_rejected()
        queue_state = self.queue_state if self.queue_state is not None else {}
        quota_state = self.quota_state if self.quota_state is not None else {}
        replay_state = self.replay_state if self.replay_state is not None else {}
        scheduler_decisions = self.scheduler_decisions if self.scheduler_decisions is not None else ()
        object.__setattr__(self, "queue_state", _immutable_json_value(queue_state))
        object.__setattr__(self, "quota_state", _immutable_json_value(quota_state))
        object.__setattr__(self, "replay_state", _immutable_json_value(replay_state))
        object.__setattr__(self, "scheduler_decisions", tuple(_immutable_json_value(item) for item in no_hook_sequence_items(scheduler_decisions)))

    def as_stable_payload(self) -> dict[str, object]:
        return {
            "queue_state": _mutable_json_value(self.queue_state),
            "quota_state": _mutable_json_value(self.quota_state),
            "replay_state": _mutable_json_value(self.replay_state),
            "scheduler_decisions": _mutable_json_value(self.scheduler_decisions),
        }

    def stable_digest(self) -> str:
        return hashlib.sha256(
            json.dumps(
                self.as_stable_payload(),
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()


def _canonical_order_key(value: object) -> tuple[str, str, str]:
    canonical = canonicalize_evidence_record(value)
    if type(canonical) is dict:
        tag = exact_text_or_none(dict.get(canonical, "tag")) or exact_text_or_none(dict.get(canonical, "name")) or exact_text_or_none(dict.get(canonical, "event")) or ""
        src = exact_text_or_none(dict.get(canonical, "source")) or exact_text_or_none(dict.get(canonical, "path")) or exact_text_or_none(dict.get(canonical, "file")) or ""
        return tag.casefold(), src.casefold(), no_hook_json_sort_key(canonical)
    return no_hook_json_sort_key(canonical).casefold(), "", ""


def stable_evidence_order(items: Iterable[object]) -> list[object]:
    sequence = no_hook_sequence_items(items)
    return sorted(sequence, key=_canonical_order_key)


def deterministic_queue_order(paths: Iterable[object]) -> list[object]:
    return sorted(no_hook_sequence_items(paths), key=_path_sort_key)


def _deterministic_inventory_root(root: object) -> Path:
    if type(root) is type(Path()):
        return root
    if type(root) is str or isinstance(root, str):
        return Path(str.__str__(root))
    exception_message = "deterministic inventory root rejected"
    raise TypeError(exception_message)


def deterministic_path_inventory(root: object) -> tuple[str, ...]:
    """Return a stable relative file inventory independent of filesystem order."""
    base = _deterministic_inventory_root(root)
    if not base.exists():
        return ()
    files = [
        candidate.relative_to(base).as_posix()
        for candidate in sorted(base.rglob("*"), key=lambda item: item.as_posix().casefold())
        if candidate.is_file()
    ]
    return tuple(sorted(files, key=lambda item: item.casefold()))


def deterministic_scan_path_inventory(root: object) -> tuple[str, ...]:
    """Return deterministic scan inputs after canonical runtime-artifact exclusion.

    This is the canonical replay/corpus inventory boundary. It keeps forensic
    replay comparisons independent of filesystem enumeration order while also
    proving that generated scan outputs, locks, temp files, and queue metadata
    cannot become scan inputs on rerun.
    """
    base = _deterministic_inventory_root(root)
    if not base.exists():
        return ()
    files = [
        candidate.relative_to(base).as_posix()
        for candidate in sorted(base.rglob("*"), key=lambda item: item.as_posix().casefold())
        if candidate.is_file() and should_include_scan_path(candidate, scan_root=base)
    ]
    return tuple(sorted(files, key=lambda item: item.casefold()))


def deterministic_mode_enabled() -> bool:
    value = os.environ.get("UMIGE_DETERMINISTIC_MODE", "0")
    if type(value) is not str:
        return False
    return str.strip(str.__str__(value)).lower() in {"1", "true", "yes", "on"}


def canonicalize_evidence_record(item: object) -> object:
    if no_hook_mapping_items(item) is not None:
        return _mapping_to_ordered_dict(item, context="runtime_determinism")
    if type(item) in (list, tuple, set, frozenset):
        return [canonicalize_evidence_record(v) for v in stable_evidence_order(item)]
    return materialize_json_no_hook(item, context="runtime_determinism")


def _normalized_result_path_key(path: object) -> str:
    return _path_sort_key(path).strip().casefold()


def canonicalize_result_mapping(results: Mapping[str, object] | None) -> dict[str, object]:
    if results is None:
        return {}
    items = no_hook_mapping_items(results)
    if items is None:
        return {"runtime_result_mapping_unavailable": no_hook_failure("non_materializable_runtime_result_mapping", results)}
    out: dict[str, object] = {}
    for index, (key, item) in enumerate(sorted(items, key=lambda row: _path_sort_key(row[0]))):
        key_text, key_reason = no_hook_json_key(key, index, prefix="runtime_result_key")
        if key_text in out:
            key_text = no_hook_duplicate_key(key_text, index)
        out[key_text] = no_hook_failure(key_reason, key) if key_reason else canonicalize_evidence_record(item)
    return out


def _mapping_value_for_text_key(items: tuple[tuple[object, object], ...], wanted: str) -> object | None:
    for key, value in items:
        if exact_text_or_none(key) == wanted:
            return value
    return None


def validate_deterministic_result_records(results: Mapping[str, object] | None, *, require_verdict: bool = True) -> tuple[str, ...]:
    """Hard-fail malformed or duplicate replay/result records.

    Raw JSON mappings can contain path variants that differ only by slash style or
    case on case-insensitive filesystems. This function validates the canonical
    result boundary before deterministic comparison or persistence checks.
    """
    if results is None:
        exception_message = "result records are missing"
        raise ValueError(exception_message)
    items = no_hook_mapping_items(results)
    if items is None:
        exception_message = "result records must be a mapping"
        raise TypeError(exception_message)
    seen: dict[str, str] = {}
    ordered: list[str] = []
    for index, (key, value) in enumerate(sorted(items, key=lambda row: _path_sort_key(row[0]))):
        key_text, key_reason = no_hook_json_key(key, index, prefix="runtime_result_key")
        if key_reason:
            exception_message = "result record path key must be safe text"
            raise TypeError(exception_message)
        normalized = _normalized_result_path_key(key_text)
        if not normalized:
            exception_message = "result record has empty path key"
            raise ValueError(exception_message)
        previous = dict.get(seen, normalized)
        if previous is not None and previous != key_text:
            raise ValueError(
                _determinism_text(
                    "duplicate deterministic result record for ",
                    normalized,
                    ": ",
                    previous,
                    " and ",
                    key_text,
                )
            )
        value_items = no_hook_mapping_items(value)
        if value_items is None:
            raise TypeError(
                _determinism_result_error(
                    "result record for ", key_text, " must be a mapping"
                )
            )
        verdict = _mapping_value_for_text_key(value_items, "verdict")
        verdict_text = exact_text_or_none(verdict)
        if require_verdict and not verdict_text:
            raise ValueError(
                _determinism_result_error(
                    "result record for ", key_text, " is missing verdict"
                )
            )
        seen[normalized] = key_text
        ordered.append(key_text)
    return tuple(ordered)


def deterministic_json_dumps(payload: object) -> str:
    """Serialize replay/report payloads with stable JSON-visible ordering."""
    return json.dumps(
        canonicalize_evidence_record(payload),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


def deterministic_json_digest(payload: object) -> str:
    return hashlib.sha256(deterministic_json_dumps(payload).encode("utf-8")).hexdigest()


def snapshot_runtime_state(
    *,
    queue_state: Mapping[str, object] | None = None,
    quota_state: Mapping[str, object] | None = None,
    replay_state: Mapping[str, object] | None = None,
    scheduler_decisions: Iterable[Mapping[str, object]] | None = None,
) -> GovernanceSnapshot:
    return make_governance_snapshot(
        queue_state=canonicalize_evidence_record(queue_state if queue_state is not None else {}),
        quota_state=canonicalize_evidence_record(quota_state if quota_state is not None else {}),
        replay_state=canonicalize_evidence_record(replay_state if replay_state is not None else {}),
        scheduler_decisions=[canonicalize_evidence_record(item) for item in no_hook_sequence_items(scheduler_decisions)],
    )


def make_governance_snapshot(**parts: object) -> GovernanceSnapshot:
    queue_state = dict.get(parts, "queue_state")
    quota_state = dict.get(parts, "quota_state")
    replay_state = dict.get(parts, "replay_state")
    scheduler_decisions = dict.get(parts, "scheduler_decisions")
    ordered_decisions = sorted(no_hook_sequence_items(scheduler_decisions), key=deterministic_json_dumps)
    return GovernanceSnapshot(
        queue_state=_immutable_json_value(queue_state if queue_state is not None else {}),
        quota_state=_immutable_json_value(quota_state if quota_state is not None else {}),
        replay_state=_immutable_json_value(replay_state if replay_state is not None else {}),
        scheduler_decisions=tuple(_immutable_json_value(item) for item in ordered_decisions),
    )


__all__ = (
    "VOLATILE_RESULT_KEYS",
    "GovernanceSnapshot",
    "canonicalize_evidence_record",
    "canonicalize_result_mapping",
    "deterministic_json_digest",
    "deterministic_json_dumps",
    "deterministic_mode_enabled",
    "deterministic_path_inventory",
    "deterministic_queue_order",
    "deterministic_scan_path_inventory",
    "make_governance_snapshot",
    "snapshot_runtime_state",
    "stable_evidence_order",
    "validate_deterministic_result_records",
)
