"""Structured failure classes and telemetry-safe recording.

Stage 22 replaces silent exception suppression with classified, rate-limited
failure records.  Callers can still degrade safely, but failures are visible to
runtime governance and tests instead of disappearing.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from inspect import getattr_static
from types import BuiltinFunctionType, MethodType, MappingProxyType
from typing import Mapping, NoReturn, TYPE_CHECKING

from Virus_Scan.contracts.runtime_function_identity import RUNTIME_NATIVE_FUNCTION_TYPE, is_runtime_native_function
import hashlib
import os
import threading
import time
import traceback
from collections import deque
from Virus_Scan.runtime.provenance import make_failure_provenance, canonical_failure_event, reset_provenance_epoch, append_provenance_event, stable_digest
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_owner_field,
    materialize_json_no_hook,
    no_hook_mapping_items,
    no_hook_text,
    no_hook_type_name,
)
from Virus_Scan.runtime.governance_inputs import (
    runtime_bool,
    runtime_float,
    runtime_int,
)

if TYPE_CHECKING:
    from collections.abc import Callable

class FailureRecorderInternalTrail:
    """Owned bounded trail for defects inside the failure recorder itself."""

    def __init__(self, limit: int = 64) -> None:
        self._lock = threading.RLock()
        parsed_limit, issues = runtime_int(
            limit,
            field_name="failure_recorder_internal_trail_limit",
            default=64,
        )
        if issues or parsed_limit < 1:
            exception_message = "failure recorder internal trail limit rejected"
            raise ValueError(exception_message)
        self._items: deque[str] = deque(maxlen=parsed_limit)

    def append(self, where: str, exc: BaseException) -> None:
        with self._lock:
            site = _failure_token(where, default="failure_recorder_internal")
            error_type = _safe_exception_type(exc)
            message = _safe_exception_message(exc)[:240]
            self._items.append(site + ":" + error_type + ":" + message)

    def snapshot(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._items)


_FAILURE_RECORDER_INTERNAL_TRAIL = FailureRecorderInternalTrail()

_FAILURE_RECORDER_INTERNAL_ERRORS = (OSError, RuntimeError, TypeError, ValueError, UnicodeError)
_FAILURE_RECORDER_TRACE_ERRORS = (RuntimeError, TypeError, ValueError, UnicodeError)
_FAILURE_RECORDER_DIGEST_ERRORS = (RuntimeError, TypeError, ValueError, UnicodeError)
_FAILURE_RECORDER_CALLBACK_ERRORS = (OSError, RuntimeError, TypeError, ValueError, AttributeError, LookupError, UnicodeError)


_SAFE_EXACT_EXCEPTION_TYPES = (
    AssertionError,
    EOFError,
    FileNotFoundError,
    ImportError,
    LookupError,
    ModuleNotFoundError,
    NameError,
    OSError,
    PermissionError,
    RuntimeError,
    TimeoutError,
    TypeError,
    UnicodeError,
    ValueError,
)
_CALLBACK_TYPES = (BuiltinFunctionType, RUNTIME_NATIVE_FUNCTION_TYPE, MethodType)
_MAPPING_PROXY_TYPE: type[MappingProxyType] = type(MappingProxyType({}))


def _failure_text(value: object, *, default: str = "") -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="failure_text_missing",
        unsupported_reason="failure_text_unsupported",
    )
    if reason:
        return default
    return text


def _failure_token(value: object, *, default: str = "runtime", limit: int = 160) -> str:
    text = _failure_text(value, default=default).strip().lower().replace(" ", "_")
    return (text[:limit] if text else default)


def _exception_args_tuple(exc: BaseException) -> tuple[object, ...] | None:
    if type(exc) not in _SAFE_EXACT_EXCEPTION_TYPES:
        return None
    try:
        args = BaseException.__getattribute__(exc, "args")
    except _FAILURE_RECORDER_TRACE_ERRORS:
        return ("exception_args_unavailable", no_hook_type_name(exc))
    if type(args) is tuple:
        return args
    return None


def _safe_exception_message(exc: BaseException | str) -> str:
    if type(exc) is str:
        return str.__str__(exc)[:500]
    if not isinstance(exc, BaseException):
        return _failure_text(exc, default=no_hook_type_name(exc))[:500]
    args = _exception_args_tuple(exc)
    if args is None:
        return no_hook_type_name(exc)[:500]
    if len(args) == 0:
        return ""
    if len(args) == 1:
        text, reason = no_hook_text(
            tuple.__getitem__(args, 0),
            missing_reason="failure_message_missing",
            unsupported_reason="failure_message_unsupported",
        )
        return (text if not reason else no_hook_type_name(exc))[:500]
    materialized = materialize_json_no_hook(args, context="failure_exception_args", max_depth=3, max_items=8)
    if type(materialized) in (list, tuple):
        parts: list[str] = []
        for item in materialized[:8]:
            text, reason = no_hook_text(
                item,
                missing_reason="failure_message_part_missing",
                unsupported_reason="failure_message_part_unsupported",
            )
            parts.append(text if not reason else no_hook_type_name(item))
        return ", ".join(parts)[:500]
    return no_hook_type_name(exc)[:500]


def safe_exception_message(exc: BaseException | str) -> str:
    """Return bounded exception text without caller-owned conversion hooks."""
    return _safe_exception_message(exc)


def _safe_exception_type(exc: BaseException | str) -> str:
    if isinstance(exc, BaseException):
        return no_hook_type_name(exc)
    return "Failure"


def _safe_runtime_failure_domain(exc: BaseException) -> str | None:
    try:
        domain = type.__getattribute__(type(exc), "domain")
    except (AttributeError, TypeError) as domain_exc:
        _record_failure_recorder_internal_error("failure_runtime_domain_lookup", domain_exc)
        return "runtime"
    if type(domain) is str:
        return _failure_token(domain, default="runtime")
    return None


def _safe_context_mapping(context: Mapping[str, object] | None) -> dict[str, object]:
    if context is None:
        return {}
    materialized = materialize_json_no_hook(context, context="failure_context", max_depth=5, max_items=64)
    if type(materialized) is dict:
        return materialized
    return {
        "context_unavailable_reason": "non_materializable_failure_context",
        "context_type": no_hook_type_name(context),
    }


def _freeze_materialized_failure_value(value: object) -> object:
    if type(value) is dict:
        items = no_hook_mapping_items(value)
        if items is None:
            return FrozenFailureProvenance({
                "failure_context_unavailable": "failure_context_mapping_rejected"
            })
        return FrozenFailureProvenance({
            str.__str__(key) if type(key) is str else _failure_token(key, default="failure_context_key"): _freeze_materialized_failure_value(item)
            for key, item in items
        })
    if type(value) in (list, tuple):
        return tuple(_freeze_materialized_failure_value(item) for item in value)
    return value


@dataclass(frozen=True)
class _TelemetryCallbackProbe:
    callback: object | None
    unavailable_reason: str


def _telemetry_event_callback(
    telemetry: object,
    *,
    static_lookup: Callable[[type, str, object], object] = getattr_static,
) -> _TelemetryCallbackProbe:
    if telemetry is None:
        return _TelemetryCallbackProbe(None, "failure_telemetry_absent")
    try:
        raw = static_lookup(type(telemetry), "event", None)
    except (AttributeError, TypeError) as callback_exc:
        _record_failure_recorder_internal_error("failure_telemetry_callback_lookup", callback_exc)
        return _TelemetryCallbackProbe(None, "failure_telemetry_callback_lookup_failed")
    if is_runtime_native_function(raw):
        return _TelemetryCallbackProbe(raw, "")
    return _TelemetryCallbackProbe(None, "failure_telemetry_callback_unavailable")


def _logger_callback(logger: object) -> object | None:
    if isinstance(logger, _CALLBACK_TYPES):
        return logger
    return None

def _record_failure_recorder_internal_error(where: str, exc: BaseException) -> None:
    """Non-recursive emergency sink for failure-recorder failures.

    This is the terminal recorder-failure boundary.  The function must never
    raise back into callers that are already recording a failure, but it also
    must not use an explicit clean sentinel from a broad exception path.
    If the bounded trail itself is unavailable there is no deeper mutable owner
    to call without risking recursion, so the handler intentionally falls
    through after the failed emergency write attempt.
    """
    try:
        _FAILURE_RECORDER_INTERNAL_TRAIL.append(where, exc)
    except _FAILURE_RECORDER_INTERNAL_ERRORS as trail_exc:
        try:
            site = _failure_token(where, default="failure_recorder_internal")
            line = "umige_failure_recorder_internal_error:" + site + ":" + _safe_exception_type(exc) + ":" + _safe_exception_type(trail_exc) + "\n"
            os.write(2, line.encode("utf-8", "replace"))
        except OSError:
            _ = trail_exc


def failure_recorder_internal_errors() -> tuple[str, ...]:
    return _FAILURE_RECORDER_INTERNAL_TRAIL.snapshot()


class UMIGERuntimeFailure(RuntimeError):
    domain = "runtime"


def _failure_trace_tail(
    exc: BaseException | str,
    *,
    limit: int = 8,
    formatter: Callable[..., list[str]] | Callable[..., tuple[str, ...]] | None = None,
) -> str:
    """Return a bounded traceback tail for forensic attribution.

    Suppressed paths are allowed to continue only when their failure remains
    reconstructable.  Earlier stages recorded type/message/count but often lost
    the causal stack.  Keep the tail bounded so hot retry paths cannot leak
    unbounded memory while preserving where the suppression originated.

    ``formatter`` is a direct deterministic dependency seam for exercising the
    recorder-failure boundary without replacing attributes on the ``traceback``
    module at runtime.  Production callers leave it unset and use Python's
    canonical traceback formatter.
    """
    if not isinstance(exc, BaseException):
        return ""
    try:
        if type(exc) not in _SAFE_EXACT_EXCEPTION_TYPES or _exception_args_tuple(exc) is None:
            return "trace_unavailable:unsafe_exception_traceback_not_materialized_without_hooks"
        if formatter is None:
            tb = ''.join(traceback.format_tb(exc.__traceback__, limit=limit))
        else:
            tb = ''.join(formatter(type(exc), exc, exc.__traceback__, limit=limit))
        summary = _safe_exception_type(exc)
        message = _safe_exception_message(exc)
        if message:
            summary = summary + ": " + message
        return (tb + summary)[-4096:]
    except _FAILURE_RECORDER_TRACE_ERRORS as trace_exc:
        _record_failure_recorder_internal_error("failure_trace_tail", trace_exc)
        return "trace_unavailable:" + _safe_exception_type(trace_exc)


def _failure_fingerprint(domain: str, where: str, error_type: str, message: str, trace_tail: str = "") -> str:
    try:
        raw = "|".join((
            _failure_text(domain, default="runtime"),
            _failure_text(where, default="unknown"),
            _failure_text(error_type, default="Failure"),
            _failure_text(message, default=""),
            _failure_text(trace_tail, default="")[-512:],
        ))
        return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:24]
    except _FAILURE_RECORDER_DIGEST_ERRORS:
        return "failure_fingerprint_unavailable"


def _runtime_correlation_id(domain: str, where: str, error_type: str, fingerprint: str) -> str:
    """Replay-stable correlation id for suppressed/degraded failures.

    Stage108 removes pid/tid from the identifier.  Worker identity still lives in
    provenance context, but correlation IDs must compare equal across replay runs
    and across thread scheduling interleavings.
    """
    try:
        return stable_digest("correlation", domain, where, error_type, fingerprint)
    except _FAILURE_RECORDER_DIGEST_ERRORS:
        return ":".join((
            _failure_text(domain, default="runtime"),
            _failure_text(where, default="unknown"),
            _failure_text(error_type, default="Failure"),
            _failure_text(fingerprint, default="failure_fingerprint_unavailable"),
        ))


def suppression_continuation_policy(domain: str | None, where: str | None, exc: BaseException | str, *, fatal: bool = False) -> tuple[bool, str]:
    """Classify whether a caught failure is safe to continue past.

    This does not raise by itself; it gives every broad suppression a durable,
    queryable policy marker so remediation/audit tooling can distinguish
    benign optional-feature degradation from queue/persistence/scoring failures
    that must be treated as integrity-affecting.
    """
    d = classify_exception(exc, domain).lower()
    w = _failure_token(where, default="unknown").lower()
    et = _safe_exception_type(exc).lower() if isinstance(exc, BaseException) else "failure"
    msg = _safe_exception_message(exc).lower()[:200]
    text = d + " " + w + " " + et + " " + msg
    if fatal:
        return True, "fatal_explicit"
    integrity_terms = (
        "queue", "persist", "json", "atomic", "write", "replace",
        "flush", "fsync", "cache", "replay", "schema", "score",
        "result", "worker", "claim", "retry", "rollback", "cleanup",
    )
    unsafe_domains = {"queue", "persistence", "scheduler", "replay", "cache", "scoring"}
    unsafe_exc = ("json", "valueerror", "oserror", "permission", "timeout", "runtimeerror", "ioerror")
    if d in unsafe_domains and any(term in text for term in integrity_terms):
        return True, "unsafe_integrity_boundary"
    if any(term in text for term in ("atomic", "fsync", "replace", "queue_failure", "failure_info", "score_explained", "result_boundary")):
        return True, "unsafe_integrity_boundary"
    if any(term in text for term in ("telemetry", "optional", "feature_probe", "env_config", "resource_usage")):
        return False, "safe_optional_degrade"
    if any(x in et for x in unsafe_exc) and any(term in text for term in integrity_terms):
        return True, "unsafe_exception_at_integrity_boundary"
    return False, "safe_degrade"




class FrozenFailureProvenance(dict):
    """JSON-serializable immutable mapping for FailureRecord provenance."""

    def _blocked(self, *args: object, **kwargs: object) -> NoReturn:
        del args, kwargs
        raise TypeError("failure_provenance_is_immutable")

    def __setitem__(self, key: object, value: object) -> NoReturn:
        self._blocked(key, value)

    def __delitem__(self, key: object) -> NoReturn:
        self._blocked(key)

    def clear(self) -> NoReturn:
        self._blocked()

    def pop(self, key: object, default: object = None) -> NoReturn:
        self._blocked(key, default)

    def popitem(self) -> NoReturn:
        self._blocked()

    def setdefault(self, key: object, default: object = None) -> NoReturn:
        self._blocked(key, default)

    def update(self, *args: object, **kwargs: object) -> NoReturn:
        self._blocked(*args, **kwargs)

    def __deepcopy__(self, memo: dict[int, object]) -> "FrozenFailureProvenance":
        items = no_hook_mapping_items(self, allow_dict_subclass=True)
        if items is None:
            return FrozenFailureProvenance({
                "failure_context_unavailable": "failure_context_mapping_rejected"
            })
        return FrozenFailureProvenance({key: _freeze_failure_value(value) for key, value in items})


def _freeze_failure_value(value: object) -> object:
    if type(value) is FrozenFailureProvenance:
        items = no_hook_mapping_items(value, allow_dict_subclass=True)
        if items is None:
            return FrozenFailureProvenance({
                "failure_context_unavailable": "failure_context_mapping_rejected"
            })
        return FrozenFailureProvenance({key: _freeze_failure_value(item) for key, item in items})
    materialized = materialize_json_no_hook(value, context="failure_value", max_depth=8, max_items=128)
    return _freeze_materialized_failure_value(materialized)


def _materialize_failure_value(value: object) -> object:
    if type(value) is FrozenFailureProvenance or type(value) is dict:
        items = no_hook_mapping_items(value, allow_dict_subclass=type(value) is FrozenFailureProvenance)
        if items is None:
            return {"failure_context_unavailable": "failure_context_mapping_rejected"}
        return {
            str.__str__(key) if type(key) is str else _failure_token(key, default="failure_key"): _materialize_failure_value(item)
            for key, item in items
        }
    if type(value) is tuple:
        return [_materialize_failure_value(item) for item in value]
    if type(value) is list:
        return [_materialize_failure_value(item) for item in value]
    return value


@dataclass(frozen=True)
class FailureRecord:
    domain: str
    where: str
    error_type: str
    message: str
    count: int = 1
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    degraded: bool = True
    suppressed: bool = False
    trace_tail: str = ""
    fingerprint: str = ""
    correlation_id: str = ""
    fatal: bool = False
    unsafe_to_continue: bool = False
    continuation_policy: str = "safe_degrade"
    provenance: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self) is not FailureRecord:
            exception_message = "failure record owner rejected"
            raise TypeError(exception_message)
        count, count_issues = runtime_int(
            self.count,
            field_name="failure_record_count",
            default=1,
        )
        first_seen, first_seen_issues = runtime_float(
            self.first_seen,
            field_name="failure_record_first_seen",
            default=0.0,
            minimum=0.0,
        )
        last_seen, last_seen_issues = runtime_float(
            self.last_seen,
            field_name="failure_record_last_seen",
            default=0.0,
            minimum=0.0,
        )
        boolean_values: dict[str, bool] = {}
        boolean_issues: tuple[Mapping[str, object], ...] = ()
        for field_name in (
            "degraded",
            "suppressed",
            "fatal",
            "unsafe_to_continue",
        ):
            parsed, issues = runtime_bool(
                no_hook_exact_owner_field(self, FailureRecord, field_name),
                field_name="failure_record_" + field_name,
                default=False,
            )
            boolean_values[field_name] = parsed
            boolean_issues += issues
        if (
            count_issues
            or first_seen_issues
            or last_seen_issues
            or boolean_issues
        ):
            exception_message = "failure record scalar field rejected"
            raise ValueError(exception_message)
        object.__setattr__(self, "count", count)
        object.__setattr__(self, "first_seen", first_seen)
        object.__setattr__(self, "last_seen", last_seen)
        for field_name, parsed in tuple(dict.items(boolean_values)):
            object.__setattr__(self, field_name, parsed)
        provenance = {} if self.provenance is None else self.provenance
        object.__setattr__(self, "provenance", _freeze_failure_value(provenance))

    def as_record_dict(self) -> dict[str, object]:
        return {
            "domain": self.domain,
            "where": self.where,
            "error_type": self.error_type,
            "message": self.message,
            "count": self.count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "degraded": self.degraded,
            "suppressed": self.suppressed,
            "trace_tail": self.trace_tail,
            "fingerprint": self.fingerprint,
            "correlation_id": self.correlation_id,
            "fatal": self.fatal,
            "unsafe_to_continue": self.unsafe_to_continue,
            "continuation_policy": self.continuation_policy,
            "provenance": _materialize_failure_value(self.provenance),
        }


_MAX_FAILURE_RECORDS = 2048


class FailureRecordStore:
    """Explicit owner for mutable failure telemetry state.

    The previous module-level dict + lock pair made ownership implicit and easy
    to mutate from new code.  Keep public API parity while routing all mutation
    through this store so lifecycle/reset semantics are centralized.
    """

    def __init__(self, *, max_records: int = _MAX_FAILURE_RECORDS) -> None:
        self._lock = threading.RLock()
        self._records: dict[tuple[str, str, str], FailureRecord] = {}
        self._max_records, issues = runtime_int(
            max_records,
            field_name="failure_record_store_max_records",
            default=_MAX_FAILURE_RECORDS,
        )
        if issues or self._max_records < 1:
            exception_message = "failure record store max records rejected"
            raise ValueError(exception_message)

    def update_or_create(
        self,
        key: tuple[str, str, str],
        factory: Callable[[], FailureRecord],
        updater: Callable[[FailureRecord], FailureRecord | None],
    ) -> FailureRecord:
        with self._lock:
            rec = self._records.get(key)
            if rec is None:
                if len(self._records) >= self._max_records:
                    oldest = min(tuple(dict.items(self._records)), key=lambda kv: (kv[1].last_seen, kv[0]))[0]
                    self._records.pop(oldest, None)
                rec = factory()
                self._records[key] = rec
            updated = updater(rec)
            if updated is not None:
                rec = updated
                self._records[key] = rec
            return rec

    def snapshot(self, *, canonical: bool = False) -> dict[str, object]:
        with self._lock:
            values = sorted(dict.values(self._records), key=lambda r: (r.domain, r.where, r.error_type))
            if canonical:
                return {"records": [canonical_failure_event(rec.as_record_dict()) for rec in values]}
            return {"records": [rec.as_record_dict() for rec in values]}

    def clear(self) -> None:
        with self._lock:
            self._records.clear()


_FAILURE_STORE = FailureRecordStore()


def classify_exception(exc: BaseException | str, domain: str | None = None) -> str:
    if domain is not None:
        domain_text = _failure_token(domain, default="")
        if domain_text:
            return domain_text
    if isinstance(exc, UMIGERuntimeFailure):
        runtime_domain = _safe_runtime_failure_domain(exc)
        if runtime_domain:
            return runtime_domain
    name = _safe_exception_type(exc).lower() if isinstance(exc, BaseException) else _failure_text(exc, default="runtime_failure").lower()
    if "zip" in name or "archive" in name or "extract" in name:
        return "extraction"
    if "json" in name or "unicode" in name or "decode" in name or "parse" in name:
        return "parse"
    if "timeout" in name or "budget" in name or "quota" in name:
        return "budget"
    if "queue" in name:
        return "queue"
    return "runtime"


def failure_tag(domain: str, where: str | None = None) -> str:
    d = _failure_token(domain, default="runtime")
    w = _failure_token(where, default="", limit=200) if where is not None else ""
    return "failure_" + d + ("_" + w if w else "")


def _failure_log_line(rec: FailureRecord) -> str:
    return (
        "["
        + rec.domain
        + "] "
        + rec.where
        + ": "
        + rec.error_type
        + ": "
        + rec.message
        + " fingerprint="
        + rec.fingerprint
        + " correlation="
        + rec.correlation_id
        + " policy="
        + rec.continuation_policy
    )


def record_failure(
    domain: str,
    where: str,
    exc: BaseException | str,
    *,
    telemetry: object = None,
    logger: object = None,
    important: bool = False,
    suppressed: bool = False,
    fatal: bool = False,
    context: Mapping[str, object] | None = None,
    trace_formatter: Callable[..., list[str]] | Callable[..., tuple[str, ...]] | None = None,
) -> FailureRecord:
    safe_important = important is True
    safe_suppressed = suppressed is True
    safe_fatal_input = fatal is True
    d = classify_exception(exc, domain)
    w = _failure_token(where, default="unknown", limit=240)
    et = _safe_exception_type(exc)
    msg = _safe_exception_message(exc)
    trace_tail = _failure_trace_tail(exc, formatter=trace_formatter)
    fingerprint = _failure_fingerprint(d, w, et, msg, trace_tail)
    correlation_id = _runtime_correlation_id(d, w, et, fingerprint)
    key = (d, w, et)
    now = time.time()
    unsafe_to_continue, continuation_policy = suppression_continuation_policy(d, w, exc, fatal=safe_fatal_input)
    fatal = safe_fatal_input or unsafe_to_continue
    safe_context = _safe_context_mapping(context)
    provenance = make_failure_provenance(
        domain=d, where=w, error_type=et, message=msg,
        fingerprint=fingerprint, correlation_id=correlation_id,
        fatal=fatal, unsafe_to_continue=unsafe_to_continue,
        continuation_policy=continuation_policy, context=safe_context,
    ).to_json()
    def _new_record() -> FailureRecord:
        return FailureRecord(d, w, et, msg, 0, now, now, degraded=True, suppressed=safe_suppressed, trace_tail=trace_tail, fingerprint=fingerprint, correlation_id=correlation_id, fatal=fatal, unsafe_to_continue=unsafe_to_continue, continuation_policy=continuation_policy, provenance=_freeze_failure_value(provenance))

    def _update_record(rec: FailureRecord) -> FailureRecord:
        next_unsafe = rec.unsafe_to_continue or unsafe_to_continue
        next_policy = continuation_policy if next_unsafe else rec.continuation_policy
        return replace(
            rec,
            count=rec.count + 1,
            last_seen=now,
            message=msg,
            trace_tail=trace_tail or rec.trace_tail,
            fingerprint=fingerprint or rec.fingerprint,
            correlation_id=correlation_id or rec.correlation_id,
            suppressed=rec.suppressed or safe_suppressed,
            fatal=rec.fatal or fatal,
            unsafe_to_continue=next_unsafe,
            continuation_policy=next_policy,
            provenance=_freeze_failure_value(provenance),
        )

    rec = _FAILURE_STORE.update_or_create(key, _new_record, _update_record)
    try:
        append_provenance_event({
            "event_type": "failure_recorded",
            "domain": rec.domain,
            "where": rec.where,
            "error_type": rec.error_type,
            "fingerprint": rec.fingerprint,
            "correlation_id": rec.correlation_id,
            "fatal": rec.fatal,
            "unsafe_to_continue": rec.unsafe_to_continue,
            "continuation_policy": rec.continuation_policy,
            "provenance": rec.provenance,
        })
    except _FAILURE_RECORDER_CALLBACK_ERRORS as internal_exc:
        _record_failure_recorder_internal_error("append_provenance_event", internal_exc)
    try:
        event_probe = _telemetry_event_callback(telemetry)
        event_callback = event_probe.callback
        if event_callback is not None:
            event_callback(telemetry,
                "failure", rec.domain, where=rec.where, error_type=rec.error_type,
                message=rec.message, important=safe_important, suppressed=rec.suppressed,
                fatal=rec.fatal, unsafe_to_continue=rec.unsafe_to_continue,
                continuation_policy=rec.continuation_policy,
                fingerprint=rec.fingerprint, correlation_id=rec.correlation_id,
                trace_tail=rec.trace_tail, provenance=rec.provenance,
            )
    except _FAILURE_RECORDER_CALLBACK_ERRORS as internal_exc:
        # Telemetry failure must not recurse into the failure recorder, but it
        # must remain visible through the non-recursive emergency sink.
        _record_failure_recorder_internal_error("failure_telemetry", internal_exc)
    try:
        logger_callback = _logger_callback(logger)
        if logger_callback is not None:
            logger_callback(_failure_log_line(rec))
    except _FAILURE_RECORDER_CALLBACK_ERRORS as internal_exc:
        _record_failure_recorder_internal_error("failure_logger", internal_exc)
    return rec


def record_suppressed_failure(where: str, exc: BaseException | str, *, domain: str | None = None, tags: list[str] | None = None, telemetry: object = None, logger: object = None, fatal: bool = False, context: Mapping[str, object] | None = None) -> str:
    domain_text = _failure_token(domain, default="") if domain is not None else ""
    rec = record_failure(domain_text or classify_exception(exc), where, exc, telemetry=telemetry, logger=logger, suppressed=True, fatal=fatal is True, context=context)
    tag = failure_tag(rec.domain, rec.where)
    if type(tags) is list:
        present = False
        for item in tags:
            if type(item) is str and item == tag:
                present = True
                break
        if not present:
            tags.append(tag)
    return tag


def failure_snapshot() -> dict[str, object]:
    return _FAILURE_STORE.snapshot(canonical=False)

def canonical_failure_snapshot() -> dict[str, object]:
    return _FAILURE_STORE.snapshot(canonical=True)


def clear_failure_records() -> None:
    """Test/worker lifecycle helper: clear bounded failure telemetry."""
    _FAILURE_STORE.clear()
    reset_provenance_epoch()


__all__ = (
    "FailureRecord",
    "FailureRecordStore",
    "UMIGERuntimeFailure",
    "canonical_failure_snapshot",
    "classify_exception",
    "clear_failure_records",
    "failure_recorder_internal_errors",
    "failure_snapshot",
    "failure_tag",
    "record_failure",
    "record_suppressed_failure",
    "safe_exception_message",
    "suppression_continuation_policy",
)

# Stage66 typed convenience wrappers. These keep hot modules from importing the
# generic failure recorder repeatedly and force domain ownership into the API.
def record_scheduler_suppressed(where: str, exc: BaseException | str, *, tags: list[str] | None = None) -> str:
    return record_suppressed_failure(where, exc, domain="scheduler", tags=tags)

def record_detection_suppressed(where: str, exc: BaseException | str, *, tags: list[str] | None = None) -> str:
    return record_suppressed_failure(where, exc, domain="detection", tags=tags)

def record_scanner_suppressed(where: str, exc: BaseException | str, *, tags: list[str] | None = None) -> str:
    return record_suppressed_failure(where, exc, domain="scanner", tags=tags)
