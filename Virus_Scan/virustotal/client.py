"""Canonical code-owned VirusTotal API client."""
from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from types import MappingProxyType
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text, no_hook_type_name
from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS
from Virus_Scan.virustotal.config import VirusTotalConfig

VIRUSTOTAL_API_HOST = "www.virustotal.com"
VIRUSTOTAL_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
VIRUSTOTAL_ANALYSIS_PREFIX = "https://www.virustotal.com/api/v3/analyses/"
_ERROR_ACTIONS = MappingProxyType({
    "BadRequestError": "fail_request",
    "InvalidArgumentError": "fail_request",
    "NotAvailableYet": "retry_later",
    "UnselectiveContentQueryError": "fail_request",
    "UnsupportedContentQueryError": "fail_request",
    "AuthenticationRequiredError": "disable_vt",
    "UserNotActiveError": "disable_vt",
    "WrongCredentialsError": "disable_vt",
    "ForbiddenError": "skip_vt",
    "NotFoundError": "not_found",
    "AlreadyExistsError": "already_exists",
    "FailedDependencyError": "retry_later",
    "QuotaExceededError": "quota_stop",
    "TooManyRequestsError": "rate_limit_wait",
    "TransientError": "retry",
    "DeadlineExceededError": "retry",
})


def _mapping_get(mapping: object, key: str, default: object = None) -> object:
    items = no_hook_mapping_items(mapping)
    if items is None:
        return default
    for candidate, value in items:
        if type(candidate) is str and str.__eq__(candidate, key):
            return value
    return default


def _text(value: object, default: str = "") -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="virustotal_client_text_missing",
        unsupported_reason="virustotal_client_text_rejected",
    )
    if reason:
        return default
    return str.strip(text)


def _error_payload(exc: urllib.error.HTTPError) -> dict[str, object]:
    try:
        raw = exc.read().decode("utf-8", "replace")
        data = json.loads(raw) if raw else {}
        return data if type(data) is dict else {}
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        return {}


def _error_code(payload: object) -> str:
    error = _mapping_get(payload, "error", {})
    if no_hook_mapping_items(error) is None:
        return ""
    return _text(_mapping_get(error, "code"))


def classify_error(exc: object) -> tuple[str, str, dict[str, object]]:
    if type(exc) is urllib.error.HTTPError:
        payload = _error_payload(exc)
        code = _error_code(payload)
        action = dict.get(_ERROR_ACTIONS, code)
        if not action:
            if exc.code == 429:
                action = "rate_limit_wait"
            elif exc.code in (503, 504):
                action = "retry"
            elif exc.code == 401:
                action = "disable_vt"
            elif exc.code == 403:
                action = "skip_vt"
            elif exc.code == 404:
                action = "not_found"
            else:
                action = "fail_request"
        return code or "HTTP_" + int.__str__(exc.code), action, payload
    return no_hook_type_name(exc), "retry", {}


@dataclass(frozen=True, slots=True)
class VirusTotalClient:
    config: VirusTotalConfig
    api_key: str = field(repr=False)

    def __post_init__(self) -> None:
        if type(self) is not VirusTotalClient:
            raise TypeError("virustotal_client_owner_invalid")
        if type(self.config) is not VirusTotalConfig:
            raise TypeError("virustotal_client_config_invalid")
        if not self.config.enabled:
            raise ValueError("virustotal_client_config_disabled")
        if type(self.api_key) is not str or self.api_key == "":
            raise ValueError("virustotal_client_api_key_missing")

    @staticmethod
    def probe_connectivity(timeout_sec: float) -> bool:
        if type(timeout_sec) not in (int, float) or type(timeout_sec) is bool:
            raise TypeError("virustotal_network_timeout_invalid")
        timeout = float(timeout_sec)
        if not 0.1 <= timeout <= 120.0:
            raise ValueError("virustotal_network_timeout_invalid")
        try:
            with socket.create_connection((VIRUSTOTAL_API_HOST, 443), timeout=timeout):
                return True
        except OSError:
            return False

    def _request_json(
        self,
        url: str,
        *,
        method: str = "GET",
        body: bytes | None = None,
        content_type: str | None = None,
    ) -> object:
        if type(url) is not str or not (
            url == VIRUSTOTAL_UPLOAD_URL or url.startswith(VIRUSTOTAL_ANALYSIS_PREFIX)
        ):
            raise ValueError("virustotal_endpoint_rejected")
        headers = {"x-apikey": self.api_key, "User-Agent": "UMIGE-VirusTotal/1.0"}
        if content_type is not None:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        with urllib.request.urlopen(request, timeout=self.config.timeout_sec) as response:
            raw = response.read().decode("utf-8", "replace")
        try:
            return json.loads(raw)
        except (ValueError, TypeError, json.JSONDecodeError):
            return {"raw": raw}

    def call_with_retries(self, owner: object, *args: object) -> tuple[object | None, dict[str, object] | None]:
        if not callable(owner):
            raise TypeError("virustotal_client_call_owner_invalid")
        attempts = self.config.max_retries if self.config.retry_transient_errors else 1
        delay = self.config.retry_delay_seconds
        last_error: dict[str, object] | None = None
        for attempt in range(attempts):
            try:
                return owner(*args), None
            except IO_CONFIGURATION_ERRORS as exc:
                code, action, payload = classify_error(exc)
                last_error = {"code": code, "action": action, "payload": payload}
                if action not in {"retry", "retry_later", "rate_limit_wait"} or attempt + 1 >= attempts:
                    break
                if delay > 0:
                    time.sleep(delay)
        return None, last_error

    def get_analysis(self, analysis_id: object) -> object:
        identifier = _text(analysis_id)
        if identifier == "":
            raise ValueError("virustotal_analysis_id_invalid")
        url = VIRUSTOTAL_ANALYSIS_PREFIX + urllib.parse.quote(identifier, safe="")
        return self._request_json(url)

    def upload_file(self, file_path: Path) -> object:
        if type(file_path) is not Path:
            raise TypeError("virustotal_upload_path_invalid")
        boundary = "UMIGE" + int.__str__(int(time.time() * 1000))
        name = file_path.name
        head = (
            "--" + boundary + "\r\n"
            'Content-Disposition: form-data; name="file"; filename="' + name + '"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode("utf-8")
        tail = ("\r\n--" + boundary + "--\r\n").encode("utf-8")
        with file_path.open("rb") as stream:
            body = head + stream.read() + tail
        return self._request_json(
            VIRUSTOTAL_UPLOAD_URL,
            method="POST",
            body=body,
            content_type="multipart/form-data; boundary=" + boundary,
        )


__all__ = (
    "VIRUSTOTAL_ANALYSIS_PREFIX",
    "VIRUSTOTAL_API_HOST",
    "VIRUSTOTAL_UPLOAD_URL",
    "VirusTotalClient",
    "classify_error",
)
