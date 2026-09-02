"""Immutable detection failure-state ownership."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import math
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.utils.text_validation import text_boundary_value

_DETECTION_FAILURE_RECOVERABLE_EXCEPTIONS = (TypeError, ValueError, RuntimeError, OSError)
_FAILURE_SCALAR_TYPES = (int, float, bool)


def _failure_exact_text(value: object) -> str:
    """Project failure text without invoking caller-owned conversion hooks."""
    if isinstance(value, BaseException):
        try:
            args = BaseException.__getattribute__(value, "args")
        except _DETECTION_FAILURE_RECOVERABLE_EXCEPTIONS:
            args = ()
        parts = []
        if type(args) is tuple:
            for arg in args:
                text = _failure_exact_text(arg)
                if text != "":
                    parts.append(text)
        return ": ".join(parts) if len(parts) > 0 else no_hook_type_name(value)
    boundary_text = text_boundary_value(value, unsupported="")
    return boundary_text if boundary_text is not None else ""


def _safe_failure_text(value: object, default_text: str) -> str:
    try:
        replacement_text = _failure_exact_text(default_text) if default_text is not None else ''
    except _DETECTION_FAILURE_RECOVERABLE_EXCEPTIONS:
        replacement_text = ''
    try:
        if value is None:
            return replacement_text
        text = _failure_exact_text(value).strip()
    except _DETECTION_FAILURE_RECOVERABLE_EXCEPTIONS:
        return replacement_text
    if text == '':
        return replacement_text
    return text


def _safe_failure_bool(value: object, *, default_bool: bool = False) -> bool:
    if value is None:
        return default_bool
    if type(value) is bool:
        return value
    if type(value) is int and value in (0, 1):
        return value == 1
    if isinstance(value, str):
        text = str.strip(str.__str__(value)).lower()
        if text in {"true", "1", "yes", "y"}:
            return True
        if text in {"false", "0", "no", "n"}:
            return False
    return default_bool


def _unavailable_failure_record(reason: str, value: object = None) -> dict[str, object]:
    return {
        "stage_name": "detection_failure_state",
        "state": "degraded",
        "error_category": "DetectionFailureEvidenceUnavailable",
        "error_source": "detection",
        "affected_context": no_hook_type_name(value) if value is not None else "unknown",
        "confidence_degraded": True,
        "json_record_required": True,
        "replay_record_required": True,
        "fatal": False,
        "message": _safe_failure_text(reason, "detection_failure_evidence_unavailable"),
        "unavailable_reason": _safe_failure_text(reason, "detection_failure_evidence_unavailable"),
    }



def _failure_sort_key(value: object) -> str:
    if type(value) is str:
        sort_key = "str:" + str.__str__(value)
    elif type(value) is bool:
        sort_key = "bool:" + bool.__str__(value)
    elif type(value) is int:
        sort_key = "int:" + int.__str__(value)
    elif type(value) is float:
        sort_key = "float:" + float.__str__(value) if math.isfinite(value) else "float:non_finite"
    elif type(value) in (bytes, bytearray, memoryview):
        sort_key = "bytes:" + bytes(value).hex()
    else:
        sort_key = no_hook_type_name(value) + ":unavailable"
    return sort_key


def _materialize_failure_value(value: object) -> object:
    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) is float:
        return value if math.isfinite(value) else _unavailable_failure_record("detection_failure_nonfinite_float", value)
    if type(value) in (dict, MappingProxyType):
        items = tuple(value.items())
        out: dict[str, object] = {}
        for raw_key, raw_item in sorted(items, key=lambda pair: (_failure_sort_key(pair[0]), _failure_sort_key(pair[1]))):
            key_text = _safe_failure_text(raw_key, "<" + no_hook_type_name(raw_key) + ">")
            out[key_text] = _materialize_failure_value(raw_item)
        return out
    if type(value) in (tuple, list, set, frozenset):
        values = tuple(value)
        if type(value) in (set, frozenset):
            values = tuple(sorted(values, key=_failure_sort_key))
        return tuple(_materialize_failure_value(item) for item in values)
    if isinstance(value, Mapping):
        return _unavailable_failure_record("detection_failure_mapping_unavailable", value)
    return _safe_failure_text(value, "<" + no_hook_type_name(value) + ">")


@dataclass(frozen=True, slots=True)
class DetectionRecoverableFailureRequest:
    """Immutable input contract for recoverable detection failure publication."""

    stage_name: str
    error: BaseException | str
    error_source: str
    affected_context: object = ""
    confidence_degraded: bool = True
    json_record_required: bool = True
    replay_record_required: bool = True


@dataclass(frozen=True)
class DetectionFailureState:
    """Explicit recoverable/fatal failure evidence carried across detection stages."""

    stage_name: str
    state: str
    error_category: str
    error_source: str
    affected_context: str
    confidence_degraded: bool
    json_record_required: bool
    replay_record_required: bool
    fatal: bool
    message: str

    def to_record(self) -> dict[str, object]:
        return dict(asdict(self))

    @classmethod
    def from_recoverable_request(
        cls, request: DetectionRecoverableFailureRequest
    ) -> "DetectionFailureState":
        """Build recoverable failure evidence from the canonical immutable request."""
        return cls(
            stage_name=_safe_failure_text(request.stage_name, "unknown"),
            state="degraded",
            error_category=(
                no_hook_type_name(request.error)
                if isinstance(request.error, BaseException)
                else "RecoverableDetectionFailure"
            ),
            error_source=_safe_failure_text(request.error_source, "detection"),
            affected_context=_safe_failure_text(request.affected_context, ""),
            confidence_degraded=_safe_failure_bool(request.confidence_degraded, default_bool=True),
            json_record_required=_safe_failure_bool(request.json_record_required, default_bool=True),
            replay_record_required=_safe_failure_bool(request.replay_record_required, default_bool=True),
            fatal=False,
            message=_safe_failure_text(request.error, "detection_failure_message_unavailable"),
        )

    @classmethod
    def fatal_failure(
        cls,
        *,
        stage_name: str,
        error: BaseException | str,
        error_source: str,
        affected_context: object = "",
    ) -> "DetectionFailureState":
        return cls(
            stage_name=_safe_failure_text(stage_name, "unknown"),
            state="failed",
            error_category=no_hook_type_name(error) if isinstance(error, BaseException) else "FatalDetectionFailure",
            error_source=_safe_failure_text(error_source, "detection"),
            affected_context=_safe_failure_text(affected_context, ""),
            confidence_degraded=True,
            json_record_required=True,
            replay_record_required=True,
            fatal=True,
            message=_safe_failure_text(error, "detection_failure_message_unavailable"),
        )


def failure_state_records(failures: object) -> tuple[dict[str, object], ...]:
    records: list[dict[str, object]] = []
    if failures is None:
        return ()
    if type(failures) is tuple:
        values = failures
    elif type(failures) is list:
        values = tuple(failures)
    elif type(failures) in (set, frozenset):
        values = tuple(sorted(failures, key=_failure_sort_key))
    else:
        return (_unavailable_failure_record("detection_failure_iterable_unavailable", failures),)
    for failure in values:
        if isinstance(failure, DetectionFailureState):
            records.append(failure.to_record())
        elif type(failure) in (dict, MappingProxyType):
            materialized = _materialize_failure_value(failure)
            if isinstance(materialized, dict):
                records.append(materialized)
            else:
                records.append(_unavailable_failure_record("detection_failure_mapping_unavailable", failure))
        elif isinstance(failure, Mapping):
            records.append(_unavailable_failure_record("detection_failure_mapping_unavailable", failure))
    return tuple(records)


__all__ = ("DetectionRecoverableFailureRequest", "DetectionFailureState", "failure_state_records")
