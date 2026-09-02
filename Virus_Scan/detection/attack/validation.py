"""Hostile-safe validation primitives for official ATT&CK records."""
from __future__ import annotations

from Virus_Scan.contracts.numeric_boundaries import exact_bool

from Virus_Scan.contracts.text_boundaries import exact_bounded_text

from datetime import datetime
from math import isfinite
import re
from urllib.parse import ParseResult, urlparse

_ATTACK_ID = re.compile(r"^(?:T\d{4}(?:\.\d{3})?|TA\d{4}|M\d{4}|G\d{4}|S\d{4}|C\d{4}|DS\d{4}|DC\d{4}|AN\d{4}|DET\d{4})$")
_STIX_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$")
_STIX_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*--[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,127}$")
ATTACK_GIT_REF_PATTERN_TEXT = r"^(?!.*\.\.)(?!.*\/$)[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$"
_ATTACK_GIT_REF = re.compile(ATTACK_GIT_REF_PATTERN_TEXT)



def exact_https_endpoint(
    value: object,
    reason: str,
    *,
    hostname: str,
    path: str,
    allow_query: bool = False,
    maximum: int = 4096,
) -> tuple[str, ParseResult]:
    text = exact_bounded_text(value, reason, maximum=maximum)
    if type(hostname) is not str or type(path) is not str or type(allow_query) is not bool:
        raise TypeError("attack_https_endpoint_policy_invalid")
    parsed = urlparse(text)
    if (
        type(parsed) is not ParseResult
        or parsed.scheme != "https"
        or parsed.netloc != hostname
        or parsed.path != path
        or parsed.params
        or parsed.fragment
        or (parsed.query and not allow_query)
    ):
        raise ValueError(reason)
    return text, parsed


def exact_git_ref(value: object, reason: str = "attack_git_ref_invalid") -> str:
    text = exact_bounded_text(value, reason, maximum=128)
    if _ATTACK_GIT_REF.fullmatch(text) is None:
        raise ValueError(reason)
    return text


def exact_text_tuple(value: object, reason: str, *, maximum_items: int = 256) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) > maximum_items:
        raise TypeError(reason)
    out = tuple(exact_bounded_text(item, reason) for item in value)
    if len(out) != len(set(out)):
        raise ValueError(reason)
    return out


def ordered_text_tuple(value: object, reason: str, *, maximum_items: int = 256) -> tuple[str, ...]:
    out = exact_text_tuple(value, reason, maximum_items=maximum_items)
    if out != tuple(sorted(out)):
        raise ValueError(reason)
    return out


def bounded_float(value: object, reason: str, *, maximum: float = 1.0) -> float:
    if type(value) not in (int, float) or type(value) is bool:
        raise TypeError(reason)
    number = float(value)
    if not isfinite(number) or number < 0.0 or number > maximum:
        raise ValueError(reason)
    return number



def official_attack_id(value: object, reason: str = "attack_id_invalid") -> str:
    text = exact_bounded_text(value, reason, maximum=16)
    if _ATTACK_ID.fullmatch(text) is None:
        raise ValueError(reason)
    return text


def stix_id(value: object, reason: str = "attack_stix_id_invalid") -> str:
    text = exact_bounded_text(value, reason, maximum=128)
    if _STIX_ID.fullmatch(text) is None:
        raise ValueError(reason)
    return text



def stix_timestamp(value: object, reason: str = "attack_stix_timestamp_invalid") -> str:
    text = exact_bounded_text(value, reason, maximum=64)
    if _STIX_TIMESTAMP.fullmatch(text) is None:
        raise ValueError(reason)
    try:
        datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError(reason) from error
    return text


def version_text(value: object, reason: str = "attack_version_invalid") -> str:
    text = exact_bounded_text(value, reason, maximum=128)
    if _VERSION.fullmatch(text) is None:
        raise ValueError(reason)
    return text



def exact_hex(value: object, reason: str, *, length: int) -> str:
    if type(length) is not int or type(length) is bool or length < 1:
        raise TypeError("attack_hex_length_invalid")
    text = exact_bounded_text(value, reason, maximum=length)
    if len(text) != length or any(ch not in "0123456789abcdef" for ch in text):
        raise ValueError(reason)
    return text


__all__ = (
    "ATTACK_GIT_REF_PATTERN_TEXT", "bounded_float", "exact_bool", "exact_git_ref",
    "exact_hex", "exact_https_endpoint",
    "exact_text_tuple", "official_attack_id", "ordered_text_tuple", "stix_id",
    "stix_timestamp", "version_text",
)
