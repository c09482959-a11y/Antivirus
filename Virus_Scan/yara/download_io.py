"""Bounded HTTP and atomic-file primitives for the canonical YARA downloader."""
from __future__ import annotations

import json
import os
from pathlib import Path, PosixPath, WindowsPath
import stat
import tempfile
import urllib.error
import urllib.request
from urllib.parse import ParseResult, urlparse

from Virus_Scan.runtime.api import (
    durable_replace_regular_file,
    flush_open_writable_file,
    path_contains_filesystem_alias,
    stat_result_is_filesystem_alias,
)

_PATH_TYPES = (Path, PosixPath, WindowsPath)
_USER_AGENT = "UMIGE-YARA-verified-release/2"
_RELEASE_REDIRECT_HOSTS = ("github.com", "release-assets.githubusercontent.com")


def require_real_directory(path: Path) -> None:
    if type(path) not in _PATH_TYPES:
        raise TypeError("yara_download_directory_contract_invalid")
    try:
        state = path.lstat()
    except OSError as exc:
        raise ValueError("yara_download_directory_invalid") from exc
    if (
        path_contains_filesystem_alias(path)
        or stat_result_is_filesystem_alias(state)
        or not stat.S_ISDIR(state.st_mode)
    ):
        raise ValueError("yara_download_directory_invalid")


def unique_temp(root: Path, name: str, suffix: str) -> Path:
    if type(root) not in _PATH_TYPES or type(name) is not str or type(suffix) is not str:
        raise TypeError("yara_download_temp_contract_invalid")
    require_real_directory(root)
    if name in ("", ".", "..") or "/" in name or "\\" in name:
        raise ValueError("yara_download_temp_path_invalid")
    fd, raw = tempfile.mkstemp(prefix=name + ".", suffix=suffix, dir=root)
    os.close(fd)
    return Path(raw)


def _write_bytes_temp(path: Path, data: bytes) -> None:
    if type(path) not in _PATH_TYPES or type(data) is not bytes:
        raise TypeError("yara_download_write_contract_invalid")
    require_real_directory(path.parent)
    with path.open("wb") as stream:
        stream.write(data)
        stream.flush()
        flush_open_writable_file(stream.fileno())


def atomic_promote(temp: Path, destination: Path) -> None:
    if type(temp) not in _PATH_TYPES or type(destination) not in _PATH_TYPES:
        raise TypeError("yara_download_promote_contract_invalid")
    require_real_directory(destination.parent)
    if (
        temp.parent != destination.parent
        or path_contains_filesystem_alias(temp)
        or not temp.is_file()
    ):
        raise ValueError("yara_download_promote_path_invalid")
    durable_replace_regular_file(temp, destination)


def atomic_bytes(path: Path, data: bytes) -> None:
    if type(path) not in _PATH_TYPES or type(data) is not bytes:
        raise TypeError("yara_download_atomic_contract_invalid")
    require_real_directory(path.parent)
    temp = unique_temp(path.parent, path.name, ".tmp")
    try:
        _write_bytes_temp(temp, data)
        atomic_promote(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def atomic_json(path: Path, value: dict[str, object]) -> None:
    if type(value) is not dict:
        raise TypeError("yara_download_state_contract_invalid")
    payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    atomic_bytes(path, payload)


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in out:
            raise ValueError("yara_download_state_duplicate_key")
        out[str.__str__(key)] = value
    return out


def _reject_json_constant(value: str) -> object:
    raise ValueError("yara_download_state_nonfinite_number")


def load_json_state(path: Path, *, maximum_bytes: int = 64 * 1024) -> dict[str, object] | None:
    if type(path) not in _PATH_TYPES or type(maximum_bytes) is not int or type(maximum_bytes) is bool:
        raise TypeError("yara_download_state_read_contract_invalid")
    if maximum_bytes < 2:
        raise ValueError("yara_download_state_read_bounds_invalid")
    try:
        require_real_directory(path.parent)
        if (
            path_contains_filesystem_alias(path)
            or not path.is_file()
            or path.stat().st_size > maximum_bytes
        ):
            return None
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return None
    return value if type(value) is dict else None


def _header(response: object, name: str) -> str:
    try:
        getter = object.__getattribute__(response, "getheader")
        value = getter(name)
    except (AttributeError, TypeError, ValueError):
        return ""
    return str.__str__(value) if type(value) is str else ""


def _response_url(response: object) -> str:
    try:
        getter = object.__getattribute__(response, "geturl")
        value = getter()
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("yara_http_final_url_unavailable") from exc
    if type(value) is not str:
        raise TypeError("yara_http_final_url_invalid")
    return str.__str__(value)


def _parsed_https_url(url: str, reason: str) -> ParseResult:
    if type(url) is not str:
        raise TypeError(reason)
    parsed = urlparse(str.__str__(url))
    if (
        type(parsed) is not ParseResult
        or parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.params
        or parsed.fragment
    ):
        raise ValueError(reason)
    return parsed


def _validate_final_url(initial_url: str, final_url: str, *, release_asset: bool) -> None:
    initial = _parsed_https_url(initial_url, "yara_http_initial_url_invalid")
    final = _parsed_https_url(final_url, "yara_http_final_url_invalid")
    if not release_asset:
        if final.geturl() != initial.geturl():
            raise ValueError("yara_http_api_redirect_rejected")
        return
    if initial.hostname != "github.com" or final.hostname not in _RELEASE_REDIRECT_HOSTS:
        raise ValueError("yara_http_release_redirect_rejected")
    if final.hostname == "github.com" and final.geturl() != initial.geturl():
        raise ValueError("yara_http_release_redirect_rejected")
    if final.hostname == "release-assets.githubusercontent.com":
        if not final.path.startswith("/github-production-release-asset-") or not final.query:
            raise ValueError("yara_http_release_redirect_rejected")


class _StrictRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        original = request.full_url
        release_asset = urlparse(original).hostname in _RELEASE_REDIRECT_HOSTS
        _validate_final_url(original, new_url, release_asset=release_asset)
        return super().redirect_request(request, file_pointer, code, message, headers, new_url)


def _open(request: urllib.request.Request, *, timeout: int, opener: object | None) -> object:
    if opener is None:
        return urllib.request.build_opener(_StrictRedirectHandler()).open(request, timeout=timeout)
    if not callable(opener):
        raise TypeError("yara_http_opener_invalid")
    return opener(request, timeout=timeout)


def _read_bounded(response: object, maximum: int) -> bytes:
    reader = object.__getattribute__(response, "read")
    chunks: list[bytes] = []
    total = 0
    while True:
        payload = reader(min(1024 * 1024, maximum + 1 - total))
        if type(payload) is not bytes:
            raise TypeError("yara_http_payload_bytes_required")
        if payload == b"":
            break
        total += len(payload)
        if total > maximum:
            raise ValueError("yara_http_payload_invalid")
        chunks.append(payload)
    if total == 0:
        raise ValueError("yara_http_payload_invalid")
    return b"".join(chunks)


def request_bytes(
    url: str,
    *,
    maximum: int,
    timeout: int,
    opener: object | None,
    release_asset: bool,
) -> tuple[bytes, str, str]:
    if (
        type(url) is not str
        or type(maximum) is not int
        or type(maximum) is bool
        or type(timeout) is not int
        or type(timeout) is bool
        or type(release_asset) is not bool
    ):
        raise TypeError("yara_http_request_contract_invalid")
    if maximum < 1 or timeout < 1:
        raise ValueError("yara_http_request_bounds_invalid")
    initial = _parsed_https_url(url, "yara_http_initial_url_invalid")
    if release_asset:
        if initial.hostname != "github.com":
            raise ValueError("yara_http_release_url_rejected")
    elif initial.hostname != "api.github.com":
        raise ValueError("yara_http_api_url_rejected")
    headers = {"User-Agent": _USER_AGENT}
    if not release_asset:
        headers["Accept"] = "application/vnd.github+json"
    request = urllib.request.Request(url, headers=headers)
    response = _open(request, timeout=timeout, opener=opener)
    if response is None:
        raise ValueError("yara_download_response_missing")
    with response:
        _validate_final_url(url, _response_url(response), release_asset=release_asset)
        return _read_bounded(response, maximum), _header(response, "ETag"), _header(response, "Last-Modified")


def _open_archive(url: str, *, timeout: int, opener: object | None, headers: dict[str, str]) -> object | None:
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT, **headers})
    try:
        response = _open(request, timeout=timeout, opener=opener)
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return None
        raise
    if response is None:
        raise ValueError("yara_download_response_missing")
    return response


def download_archive_temp(
    url: str,
    root: Path,
    name: str,
    *,
    maximum: int,
    timeout: int,
    opener: object | None,
    headers: dict[str, str],
) -> tuple[Path | None, str, str]:
    if (
        type(url) is not str
        or type(root) not in _PATH_TYPES
        or type(name) is not str
        or type(maximum) is not int
        or type(maximum) is bool
        or type(timeout) is not int
        or type(timeout) is bool
        or type(headers) is not dict
    ):
        raise TypeError("yara_archive_download_contract_invalid")
    if maximum < 22 or timeout < 1:
        raise ValueError("yara_archive_download_bounds_invalid")
    initial = _parsed_https_url(url, "yara_http_initial_url_invalid")
    if initial.hostname != "github.com":
        raise ValueError("yara_http_release_url_rejected")
    response = _open_archive(url, timeout=timeout, opener=opener, headers=headers)
    if response is None:
        return None, "", ""
    temp = unique_temp(root, name, ".download.tmp")
    completed = False
    try:
        with response:
            _validate_final_url(url, _response_url(response), release_asset=True)
            reader = object.__getattribute__(response, "read")
            total = 0
            with temp.open("wb") as stream:
                while True:
                    chunk = reader(1024 * 1024)
                    if chunk == b"":
                        break
                    if type(chunk) is not bytes:
                        raise TypeError("yara_archive_response_bytes_required")
                    total += len(chunk)
                    if total > maximum:
                        raise ValueError("yara_archive_download_oversized")
                    stream.write(chunk)
                stream.flush()
                flush_open_writable_file(stream.fileno())
            if total < 22:
                raise ValueError("yara_archive_download_empty")
            completed = True
            return temp, _header(response, "ETag"), _header(response, "Last-Modified")
    finally:
        if not completed and temp.exists():
            temp.unlink()


__all__ = (
    "atomic_bytes", "atomic_json", "atomic_promote", "download_archive_temp",
    "load_json_state", "request_bytes", "require_real_directory", "unique_temp",
)
