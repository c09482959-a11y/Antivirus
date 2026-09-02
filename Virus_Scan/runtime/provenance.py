"""Deterministic forensic provenance records for runtime failure/recovery paths.

Stage107 real remediation: centralizes failure attribution instead of letting
module-local broad exception handlers invent partial context.  The schema is
intentionally JSON-only and canonicalizable so replay/stress tests can compare
records without volatile wall-clock ordering.
"""
from __future__ import annotations
import json

from dataclasses import dataclass, asdict, field
from typing import Mapping
import hashlib
import threading

from Virus_Scan.contracts.no_hook_materialization import (
    materialize_json_no_hook,
    no_hook_failure,
    no_hook_json_key,
    no_hook_json_sort_key,
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_text,
)
from Virus_Scan.runtime.governance_inputs import (
    runtime_bool,
    runtime_input_rejection,
    runtime_int,
    runtime_mapping,
)

_MAX_PROVENANCE_EVENTS = 4096
_MAX_CAUSAL_CHAIN = 16
_MAX_PROVENANCE_CONTEXT_INT = 2 ** 63 - 1
_PROVENANCE_TEXT_ERRORS = (UnicodeError, ValueError, TypeError, RuntimeError)
_PROVENANCE_JSON_ERRORS = (TypeError, ValueError, OverflowError, RecursionError, UnicodeError, RuntimeError)


class ProvenanceLedger:
    """Explicit owner for mutable provenance state.

    Phase 4 removes the unowned module-level list/counter mutation pattern.
    The public module functions remain stable, but all mutation now goes through
    this owned ledger boundary with one lock and snapshot/clear methods.
    """

    def __init__(self, *, max_events: int = _MAX_PROVENANCE_EVENTS) -> None:
        self._lock = threading.RLock()
        self._epoch = 0
        self._events: list[dict[str, object]] = []
        self._max_events, issues = runtime_int(
            max_events,
            field_name="provenance_ledger_max_events",
            default=_MAX_PROVENANCE_EVENTS,
        )
        if issues or self._max_events < 1:
            exception_message = "provenance ledger max events rejected"
            raise ValueError(exception_message)

    def next_epoch(self) -> int:
        with self._lock:
            self._epoch += 1
            return self._epoch

    def append(self, event: Mapping[str, object]) -> dict[str, object]:
        record = _stable_jsonish(event)
        if type(record) is not dict:
            record = {
                "provenance_event_rejected": True,
                "input_evidence": no_hook_failure(
                    "non_materializable_provenance_event", event
                ),
            }
        with self._lock:
            if len(self._events) >= self._max_events:
                del self._events[0:max(1, len(self._events) - self._max_events + 1)]
            self._events.append(record)
        return _provenance_record_copy(record)

    def snapshot(self) -> list[dict[str, object]]:
        with self._lock:
            return [_stable_jsonish(e) for e in self._events]

    def clear(self) -> None:
        with self._lock:
            self._events.clear()

    def reset(self) -> None:
        with self._lock:
            self._epoch = 0
            self._events.clear()


_PROVENANCE_LEDGER = ProvenanceLedger()

_VOLATILE_KEYS = frozenset((
    "time", "timestamp", "iso", "last_seen", "first_seen", "pid", "tid",
    "thread", "thread_id", "process_id", "worker_pid", "claimed_at", "started_at",
    "heartbeat_time", "progress_time", "queued_at",
))


def _next_epoch() -> int:
    return _PROVENANCE_LEDGER.next_epoch()


def _provenance_exact_text(value: object) -> str:
    if type(value) is str:
        return str.__str__(value)
    if type(value) is int:
        return int.__str__(value)
    return "value"


def _provenance_join(left: object, right: object) -> str:
    return _provenance_exact_text(left) + str.__str__(right)


def _provenance_indexed(prefix: str, index: int) -> str:
    return str.__str__(prefix) + int.__str__(index)


def _provenance_record_copy(record: dict[str, object]) -> dict[str, object]:
    items = no_hook_mapping_items(record)
    if items is None:
        return {}
    return dict(items)


def _safe_text(value: object, limit: int = 240) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="provenance_text_missing",
        unsupported_reason="provenance_text_rejected",
    )
    if reason:
        text = "<unprintable>"
    return text[:limit]



def _stable_json_sort_key(value: object) -> str:
    return no_hook_json_sort_key(value)

def _stable_jsonish(value: object) -> object:
    """Return a deterministic, JSON-compatible view with volatile fields removed."""
    items = no_hook_mapping_items(value)
    if items is not None:
        keyed: list[tuple[str, int, object, str]] = []
        for index, (key, item) in enumerate(items):
            key_text, reason = no_hook_json_key(
                key, index, prefix="provenance_key"
            )
            keyed.append((key_text, index, item, reason))
        out: dict[str, object] = {}
        for sk, index, item, reason in sorted(
            keyed, key=lambda row: (row[0], row[1])
        ):
            if sk in _VOLATILE_KEYS:
                continue
            output_key = _provenance_join(sk, "#" + int.__str__(index)) if sk in out else sk
            out[output_key] = (
                no_hook_failure(reason, item)
                if reason
                else _stable_jsonish(item)
            )
        return out
    if isinstance(value, Mapping):
        return no_hook_failure("non_materializable_provenance_mapping", value)
    if type(value) in (list, tuple):
        return [_stable_jsonish(v) for v in value]
    if type(value) in (set, frozenset):
        normalized = [_stable_jsonish(v) for v in value]
        return sorted(normalized, key=no_hook_json_sort_key)
    if isinstance(value, str):
        return str.__str__(value)
    if type(value) in (int, float, bool) or value is None:
        return materialize_json_no_hook(
            value, context="provenance_scalar", max_depth=1
        )
    if type(value) in (bytes, bytearray):
        return materialize_json_no_hook(
            value, context="provenance_bytes", max_depth=1
        )
    if value is None:
        return value
    return no_hook_failure("non_materializable_provenance_value", value)


def stable_digest(*parts: object) -> str:
    payload = json.dumps(
        [_stable_jsonish(p) for p in parts],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()[:24]


@dataclass(frozen=True)
class FailureProvenance:
    schema_version: int
    event_type: str
    origin_subsystem: str
    failure_site: str
    correlation_id: str
    causal_fingerprint: str
    runtime_epoch: int
    scheduler_epoch: int
    retry_generation: int
    worker_identity: str
    queue_identity: str
    replay_identity: str
    parent_chain: tuple[str, ...]
    degradation_state: str
    escalation_decision: str
    recovery_decision: str
    input_evidence: tuple[Mapping[str, object], ...] = field(default_factory=tuple)

    def to_json(self) -> dict[str, object]:
        out = asdict(self)
        out["parent_chain"] = list(self.parent_chain)
        out["input_evidence"] = materialize_json_no_hook(
            self.input_evidence, context="provenance_input_evidence"
        )
        return out


def _coerce_parent_chain(
    parent: object,
) -> tuple[tuple[str, ...], tuple[Mapping[str, object], ...]]:
    if isinstance(parent, str):
        return (str.__str__(parent),), ()
    if parent is None:
        return (), ()
    if type(parent) not in (list, tuple, set, frozenset):
        return (), (
            runtime_input_rejection(
                "provenance_parent_chain",
                parent,
                "provenance_parent_chain_rejected",
            ),
        )
    values = no_hook_sequence_items(parent)[:_MAX_CAUSAL_CHAIN]
    out: list[str] = []
    evidence: tuple[Mapping[str, object], ...] = ()
    for index, item in enumerate(values):
        text, reason = no_hook_text(
            item,
            missing_reason="provenance_parent_missing",
            unsupported_reason="provenance_parent_rejected",
        )
        if reason:
            evidence += (
                runtime_input_rejection(
                    _provenance_indexed("provenance_parent_chain_", index), item, reason
                ),
            )
            continue
        out.append(text)
    return tuple(out), evidence


def _coerce_context_int(
    ctx: dict[str, object], keys: tuple[str, ...], default: int = 0
) -> tuple[int, tuple[Mapping[str, object], ...]]:
    value = default
    evidence: tuple[Mapping[str, object], ...] = ()
    for key in keys:
        candidate = dict.get(ctx, key, value)
        if candidate is None or (type(candidate) is str and candidate == ""):
            candidate = value
        value, issues = runtime_int(
            candidate, field_name=_provenance_join("provenance_", key), default=value
        )
        evidence += issues
        value = min(value, _MAX_PROVENANCE_CONTEXT_INT)
    return value, evidence


def _first_context_value(
    ctx: dict[str, object], keys: tuple[str, ...], default: object = ""
) -> object:
    for key in keys:
        value = dict.get(ctx, key)
        if value is None:
            continue
        if type(value) is str and value == "":
            continue
        return value
    return default


def make_failure_provenance(
    *,
    domain: str,
    where: str,
    error_type: str,
    message: str,
    fingerprint: str,
    correlation_id: str,
    fatal: bool,
    unsafe_to_continue: bool,
    continuation_policy: str,
    context: Mapping[str, object] | None = None,
) -> FailureProvenance:
    ctx, evidence = runtime_mapping(context, field_name="provenance_context")
    parent = _first_context_value(
        ctx, ("parent_chain", "causal_parent_chain"), ()
    )
    parent_chain, issues = _coerce_parent_chain(parent)
    evidence += issues
    retry_generation, issues = _coerce_context_int(
        ctx, ("retry_generation", "generation", "attempt")
    )
    evidence += issues
    scheduler_epoch, issues = _coerce_context_int(
        ctx, ("scheduler_epoch", "queue_epoch")
    )
    evidence += issues
    queue_identity = _safe_text(
        _first_context_value(
            ctx, ("queue_identity", "file_id", "file", "path")
        )
    )
    worker_identity = _safe_text(
        _first_context_value(
            ctx, ("worker_identity", "worker_id", "claimed_by")
        )
    )
    replay_value = _first_context_value(
        ctx, ("replay_identity", "replay_id"), None
    )
    if replay_value is None:
        replay_value = stable_digest(
            domain, where, error_type, queue_identity, retry_generation
        )
    replay_identity = _safe_text(replay_value)
    fatal_value, issues = runtime_bool(
        fatal, field_name="provenance_fatal", default=True
    )
    evidence += issues
    unsafe_value, issues = runtime_bool(
        unsafe_to_continue,
        field_name="provenance_unsafe_to_continue",
        default=True,
    )
    evidence += issues
    escalation = (
        "fatal"
        if fatal_value
        else ("unsafe_to_continue" if unsafe_value else "degrade")
    )
    recovery = (
        "quarantine_required"
        if unsafe_value
        else "degraded_continuation_allowed"
    )
    return FailureProvenance(
        schema_version=1,
        event_type="failure",
        origin_subsystem=_safe_text(domain or "runtime", 80),
        failure_site=_safe_text(where or "unknown", 160),
        correlation_id=_safe_text(correlation_id or stable_digest(domain, where, error_type, message), 220),
        causal_fingerprint=_safe_text(fingerprint or stable_digest(domain, where, error_type, message), 64),
        runtime_epoch=_next_epoch(),
        scheduler_epoch=scheduler_epoch,
        retry_generation=retry_generation,
        worker_identity=worker_identity,
        queue_identity=queue_identity,
        replay_identity=replay_identity,
        parent_chain=parent_chain,
        degradation_state="unsafe" if unsafe_value else "degraded",
        escalation_decision=escalation,
        recovery_decision=recovery if continuation_policy != "fatal_explicit" else "abort_or_quarantine",
        input_evidence=evidence,
    )


def canonical_failure_event(record: Mapping[str, object]) -> dict[str, object]:
    """Return replay-comparable failure event without volatile counters/times."""
    out, issues = runtime_mapping(record, field_name="canonical_failure_event")
    if issues:
        out["input_evidence"] = issues
    for key in ("count", "first_seen", "last_seen"):
        out.pop(key, None)
    prov = out.get("provenance")
    if isinstance(prov, Mapping):
        out["provenance"] = _stable_jsonish(prov)
        out["provenance"].pop("runtime_epoch", None)
    return _stable_jsonish(out)


def append_provenance_event(event: Mapping[str, object]) -> dict[str, object]:
    """Append a replay-safe provenance event to the bounded in-memory ledger.

    The ledger is intentionally append-only from caller perspective and stores a
    canonical JSON-like snapshot so later mutation of caller-owned dictionaries
    cannot rewrite failure history.  Runtime epoch is kept for live ordering;
    canonical views strip it for deterministic replay comparison.
    """
    return _PROVENANCE_LEDGER.append(event)


def provenance_snapshot(*, canonical: bool = False) -> dict[str, object]:
    events = _PROVENANCE_LEDGER.snapshot()
    if canonical:
        events = [canonical_failure_event(e) for e in events]
        events.sort(
            key=lambda event: (
                _safe_text(dict.get(event, "correlation_id", "")),
                _safe_text(dict.get(event, "origin_subsystem", "")),
                _safe_text(dict.get(event, "failure_site", "")),
            )
        )
    return {"events": events}


def clear_provenance_events() -> None:
    _PROVENANCE_LEDGER.clear()


def reset_provenance_epoch() -> None:
    _PROVENANCE_LEDGER.reset()


__all__ = (
    "FailureProvenance",
    "ProvenanceLedger",
    "append_provenance_event",
    "canonical_failure_event",
    "clear_provenance_events",
    "make_failure_provenance",
    "provenance_snapshot",
    "reset_provenance_epoch",
    "stable_digest",
)
