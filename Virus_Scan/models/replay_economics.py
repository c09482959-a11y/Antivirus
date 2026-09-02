"""Bounded replay retention/economics helpers.

Replay is valuable for regression and calibration, but it cannot be treated as
free infrastructure.  These helpers decide when replay metadata should be kept
or skipped while never disabling the canonical learning replay itself.
"""
from __future__ import annotations
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.structured_failures import record_suppressed_failure
from Virus_Scan.contracts.env_config import bool_env, int_env

from dataclasses import dataclass
import hashlib
import math
from Virus_Scan.runtime.runtime_economics_ledger import get_runtime_economics_ledger
from Virus_Scan.models.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_text,
    no_hook_type_name,
)


PLR2004N500 = 500


def _is_replay_mapping(value: object) -> bool:
    return no_hook_mapping_items(value, allow_dict_subclass=True) is not None


def _replay_exact_text(value: object, default: str = "") -> tuple[str, bool]:
    """Return detached replay text without caller-owned hooks."""
    text, reason = no_hook_text(
        value,
        missing_reason="missing_replay_text",
        unsupported_reason="unsupported_replay_text",
    )
    if reason == "":
        return text, True
    return default, False


def _replay_mapping_key_text(key: object, index: int | None = None) -> str:
    text, readable = _replay_exact_text(key, "")
    if readable and text != "":
        return text
    suffix = "" if index is None else "_" + int.__str__(index)
    return "<unreadable_replay_metadata_key" + suffix + ">"


def _finite_replay_metric(value: object, default: float = 0.0) -> float:
    candidate = default if value is None else value
    if type(candidate) is bool:
        return float(default)
    if type(candidate) is int:
        metric = float(candidate)
    elif type(candidate) is float:
        metric = candidate
    elif isinstance(candidate, str):
        try:
            metric = float(str.__str__(candidate).strip())
        except RECOVERABLE_RUNTIME_ERRORS:
            return float(default)
    elif type(candidate) is bytes:
        try:
            metric = float(bytes.decode(candidate, "utf-8", "replace").strip())
        except RECOVERABLE_RUNTIME_ERRORS:
            return float(default)
    elif type(candidate) is bytearray:
        try:
            metric = float(bytearray.decode(candidate, "utf-8", "replace").strip())
        except RECOVERABLE_RUNTIME_ERRORS:
            return float(default)
    else:
        return float(default)
    if not math.isfinite(metric):
        return float(default)
    return metric




def _replay_metadata_key_order(key: object) -> tuple[int, str, int, str]:
    default_text = "<" + no_hook_type_name(key) + ">"
    text, readable = _replay_exact_text(key, default_text)
    if not readable or text == "":
        text = default_text
    lower = text.lower()
    if len(lower) > 1 and len(lower) <= 32 and lower[0] == "k" and lower[1:].isdigit():
        return (1, "k", int(lower[1:]), lower)
    return (0, lower, -1, text)

def _json_safe_replay_metadata(value: object) -> object:
    if type(value) is float:
        if not math.isfinite(value):
            return {"value": None, "unavailable_reason": "non_finite_replay_metadata"}
        return value
    if type(value) is int:
        return value
    if isinstance(value, str):
        text, _readable = _replay_exact_text(value, "")
        return text
    if type(value) is bytes or type(value) is bytearray:
        text, readable = _replay_exact_text(value, "")
        if readable:
            return text
    if type(value) is bool or value is None:
        return value
    return {
        "value": "<" + no_hook_type_name(value) + ">",
        "unavailable_reason": "unsupported_replay_metadata_type",
    }

@dataclass(frozen=True)
class ReplayEconomicsConfig:
    max_metadata_records: int = 2000
    sample_modulo: int = 10
    divergence_always_keep: bool = True

    @classmethod
    def from_env(cls) -> "ReplayEconomicsConfig":
        return cls(
            max_metadata_records=int_env("UMIGE_REPLAY_MAX_METADATA_RECORDS", cls.max_metadata_records, 1),
            sample_modulo=int_env("UMIGE_REPLAY_SAMPLE_MODULO", cls.sample_modulo, 1),
            divergence_always_keep=bool_env("UMIGE_REPLAY_KEEP_DIVERGENCE", True),
        )


def _safe_replay_mapping_get(mapping: object, key: str) -> tuple[object, bool]:
    items = no_hook_mapping_items(mapping, allow_dict_subclass=True)
    if items is None:
        return None, False
    for item_key, item_value in items:
        if type(item_key) is str and str.__eq__(item_key, key) is True:
            return item_value, True
    return None, True


def _safe_replay_truth(value: object) -> tuple[bool, bool]:
    if value is None:
        return False, True
    if type(value) is bool:
        return value, True
    if type(value) is int:
        return value != 0, True
    if type(value) is float:
        if not math.isfinite(value):
            return True, False
        return value != 0.0, True
    text, readable = _replay_exact_text(value, "")
    if readable:
        text = str.strip(text).lower()
        if text in {"", "0", "false", "no", "off"}:
            return False, True
        if text in {"1", "true", "yes", "on"}:
            return True, True
    return True, False


def _safe_replay_index(index: object) -> tuple[int, bool]:
    if type(index) is bool:
        return 0, False
    if type(index) is int:
        return index, True
    if type(index) is float and math.isfinite(index):
        return int(index), True
    text, readable = _replay_exact_text(index, "")
    if not readable:
        return 0, False
    text = str.strip(text)
    if text == "":
        return 0, False
    sign = 1
    digits = text
    if digits[0] in "+-":
        sign = -1 if digits[0] == "-" else 1
        digits = digits[1:]
    if digits == "" or not digits.isdecimal():
        return 0, False
    return sign * int(digits, 10), True


def _replay_result_identity_text(result: object) -> tuple[str, bool]:
    path_value, path_readable = _safe_replay_mapping_get(result, "path")
    file_value, file_readable = _safe_replay_mapping_get(result, "file")
    if not path_readable or not file_readable:
        return "", False
    chosen = path_value if path_value is not None else file_value
    if chosen is None:
        return "", True
    text, readable = _replay_exact_text(chosen, "")
    if not readable:
        return "", False
    return text, True


def replay_should_retain(result: dict[str, object] | None, *, index: int = 0, config: ReplayEconomicsConfig | None = None) -> bool:
    """Return whether detailed replay metadata should be retained for this result.

    Malformed replay result containers are fail-safe retained.  Returning
    ``False`` for non-mapping input would silently discard the very replay
    evidence needed to diagnose a corrupted parent/model handoff.
    """
    try:
        get_runtime_economics_ledger().observe('replay_cost', 1.0)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        record_suppressed_failure('replay_economics_observe_failed', exc, domain='replay')
    config = config if config is not None else ReplayEconomicsConfig.from_env()
    if result is None:
        result = {}
    if not _is_replay_mapping(result):
        return True
    divergence_value, divergence_readable = _safe_replay_mapping_get(result, "replay_divergence")
    divergence, divergence_truth_readable = _safe_replay_truth(divergence_value)
    if not divergence_readable or not divergence_truth_readable:
        return True
    if config.divergence_always_keep and divergence:
        return True
    score_value, score_readable = _safe_replay_mapping_get(result, "score")
    if not score_readable:
        return True
    score = _finite_replay_metric(score_value, 0.0)
    if score >= 25.0:
        return True
    path, path_readable = _replay_result_identity_text(result)
    if not path_readable:
        return True
    if path:
        digest = int(hashlib.sha1(path.encode("utf-8", "ignore"), usedforsecurity=False).hexdigest()[:8], 16)
    else:
        digest, index_readable = _safe_replay_index(index)
        if not index_readable:
            return True
    return digest % max(1, config.sample_modulo) == 0


def replay_compress_metadata(meta: object) -> object:
    """Keep replay metadata compact and JSON-safe without caller hooks."""
    ordered_items = no_hook_mapping_items(meta, allow_dict_subclass=True)
    if ordered_items is not None:
        out = {}
        ordered_pairs = sorted(ordered_items, key=lambda item: _replay_metadata_key_order(item[0]))
        for index, (k, v) in enumerate(ordered_pairs):
            key_text = _replay_mapping_key_text(k, index)
            if key_text in {"baseline", "raw", "strings_blob", "decoded_strings"}:
                continue
            if key_text in out:
                key_text = key_text + "#" + int.__str__(index)
            out[key_text] = replay_compress_metadata(v)
            if len(out) >= 32:
                out["truncated"] = True
                break
        return out
    if type(meta) in (list, tuple):
        return [replay_compress_metadata(x) for x in meta[:32]] + ([{"truncated": True}] if len(meta) > 32 else [])
    if type(meta) in (set, frozenset):
        ordered = tuple(sorted(meta, key=lambda item: _replay_metadata_key_order(item)[1:]))
        return [replay_compress_metadata(x) for x in ordered[:32]] + ([{"truncated": True}] if len(ordered) > 32 else [])
    if isinstance(meta, str):
        text, _readable = _replay_exact_text(meta, "")
        if len(text) > PLR2004N500:
            return text[:500] + "...<truncated>"
        return text
    return _json_safe_replay_metadata(meta)


__all__ = ("ReplayEconomicsConfig", "replay_compress_metadata", "replay_should_retain")
