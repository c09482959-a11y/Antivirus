"""Hostile-safe validation primitives for YARA supply-chain records."""
from __future__ import annotations

from Virus_Scan.contracts.text_boundaries import exact_bounded_text

from math import isfinite
import re
from urllib.parse import ParseResult, urlparse

_RELEASE_TAG = re.compile(r"^[0-9]{8}$")
_ARCHIVE_ASSET_NAME = re.compile(r"^yara-forge-rules-(?:core|extended|full)\.zip$")
_RELEASE_ASSET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

RELEASE_API_URL = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
YARA_RELEASE_MANIFEST_NAME = "yara-forge-rules-sha256.txt"
_RELEASE_API_PATH = "/repos/YARAHQ/yara-forge/releases/latest"
_PACKAGE_KINDS = ("core", "extended", "full")



def exact_bool(value: object, reason: str) -> bool:
    if type(value) is not bool:
        raise TypeError(reason)
    return value is True


def bounded_int(value: object, reason: str, *, minimum: int = 0, maximum: int) -> int:
    if type(value) is not int or type(value) is bool:
        raise TypeError(reason)
    if value < minimum or value > maximum:
        raise ValueError(reason)
    return value


def bounded_float(value: object, reason: str, *, minimum: float = 0.0, maximum: float = 1.0) -> float:
    if type(value) not in (int, float) or type(value) is bool:
        raise TypeError(reason)
    number = float(value)
    if not isfinite(number) or number < minimum or number > maximum:
        raise ValueError(reason)
    return number


def sha256_text(value: object, reason: str = "yara_sha256_invalid") -> str:
    text = exact_bounded_text(value, reason, maximum=64)
    if _SHA256.fullmatch(text) is None:
        raise ValueError(reason)
    return text


def release_tag(value: object, reason: str = "yara_release_tag_invalid") -> str:
    text = exact_bounded_text(value, reason, maximum=8)
    if _RELEASE_TAG.fullmatch(text) is None:
        raise ValueError(reason)
    return text


def package_kind(value: object, reason: str = "yara_package_kind_invalid") -> str:
    text = exact_bounded_text(value, reason, maximum=16)
    if text not in _PACKAGE_KINDS:
        raise ValueError(reason)
    return text


def archive_asset_name(value: object, reason: str = "yara_archive_asset_name_invalid") -> str:
    text = exact_bounded_text(value, reason, maximum=96)
    if _ARCHIVE_ASSET_NAME.fullmatch(text) is None:
        raise ValueError(reason)
    return text


def manifest_asset_name(value: object, reason: str = "yara_manifest_asset_name_invalid") -> str:
    text = exact_bounded_text(value, reason, maximum=96)
    if text != YARA_RELEASE_MANIFEST_NAME:
        raise ValueError(reason)
    return text


def release_asset_name(value: object, reason: str = "yara_release_asset_name_invalid") -> str:
    text = exact_bounded_text(value, reason, maximum=128)
    if _RELEASE_ASSET_NAME.fullmatch(text) is None or text in (".", ".."):
        raise ValueError(reason)
    return text


def version_text(value: object, reason: str = "yara_version_invalid") -> str:
    text = exact_bounded_text(value, reason, maximum=128)
    matched = _VERSION.fullmatch(text)
    if matched is None:
        raise ValueError(reason)
    return text


def exact_text_tuple(value: object, reason: str, *, maximum_items: int = 65536) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) > maximum_items:
        raise TypeError(reason)
    out = tuple(exact_bounded_text(item, reason, maximum=4096) for item in value)
    if len(out) != len(set(out)):
        raise ValueError(reason)
    return out


def ordered_text_tuple(value: object, reason: str, *, maximum_items: int = 65536) -> tuple[str, ...]:
    out = exact_text_tuple(value, reason, maximum_items=maximum_items)
    ordered = sorted(out)
    if list(out) != ordered:
        raise ValueError(reason)
    return out


def release_api_url(value: object, reason: str = "yara_release_api_url_invalid") -> str:
    text = exact_bounded_text(value, reason, maximum=512)
    parsed = urlparse(text)
    if (
        type(parsed) is not ParseResult
        or parsed.scheme != "https"
        or parsed.netloc != "api.github.com"
        or parsed.path != _RELEASE_API_PATH
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(reason)
    return text


def release_asset_url(value: object, *, tag: str, name: str, reason: str = "yara_release_asset_url_invalid") -> str:
    text = exact_bounded_text(value, reason, maximum=2048)
    validated_name = release_asset_name(name)
    expected_path = "/YARAHQ/yara-forge/releases/download/" + release_tag(tag) + "/" + validated_name
    parsed = urlparse(text)
    if (
        type(parsed) is not ParseResult
        or parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.path != expected_path
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(reason)
    return text


__all__ = (
    "RELEASE_API_URL", "YARA_RELEASE_MANIFEST_NAME", "archive_asset_name",
    "bounded_float", "bounded_int", "exact_bool", "exact_text_tuple",
    "manifest_asset_name", "ordered_text_tuple", "package_kind", "release_api_url",
    "release_asset_name", "release_asset_url", "release_tag", "sha256_text", "version_text",
)
