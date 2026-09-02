"""Strict immutable VirusTotal configuration with code-owned endpoints."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path, PosixPath, WindowsPath
import re
import stat
import tomllib

from Virus_Scan.runtime.api import (
    path_contains_filesystem_alias,
    stat_result_is_filesystem_alias,
)

VIRUSTOTAL_CONFIG_VERSION = "virustotal_config_v2"
_MAX_CONFIG_BYTES = 64 * 1024
_PATH_TYPES = (Path, PosixPath, WindowsPath)
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_RATE_LIMIT_ACTIONS = frozenset({"skip", "stop"})


def _bounded_int(value: object, reason: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or type(value) is bool or not minimum <= value <= maximum:
        raise ValueError(reason)
    return value


def _bounded_float(value: object, reason: str, minimum: float, maximum: float) -> float:
    if type(value) not in (int, float) or type(value) is bool:
        raise TypeError(reason)
    result = float(value)
    if not minimum <= result <= maximum:
        raise ValueError(reason)
    return result


def _exact_env_name(value: object) -> str:
    if type(value) is not str:
        raise TypeError("virustotal_api_key_environment_variable_invalid")
    text = str.__str__(value)
    if _ENV_NAME.fullmatch(text) is None:
        raise ValueError("virustotal_api_key_environment_variable_invalid")
    return text


@dataclass(frozen=True, slots=True)
class VirusTotalConfig:
    config_version: str = VIRUSTOTAL_CONFIG_VERSION
    enabled: bool = False
    api_key_environment_variable: str = "VIRUSTOTAL_API_KEY"
    submit_high: bool = True
    submit_malicious: bool = True
    print_to_cli: bool = True
    print_submitted: bool = True
    print_skipped: bool = False
    write_normalized_results: bool = True
    poll_for_report: bool = True
    wait_for_full_report: bool = True
    poll_interval_sec: float = 15.0
    poll_attempts: int = 8
    poll_max_wait_sec: float = 3600.0
    poll_stable_checks: int = 2
    timeout_sec: float = 60.0
    max_upload_mb: float = 32.0
    include_full_response: bool = False
    network_check_timeout_sec: float = 3.0
    upload_rate_limit_per_minute: int = 4
    daily_upload_limit: int = 500
    rate_limit_action: str = "skip"
    retry_transient_errors: bool = True
    max_retries: int = 3
    retry_delay_seconds: float = 20.0

    def __post_init__(self) -> None:
        if type(self) is not VirusTotalConfig:
            raise TypeError("virustotal_config_owner_invalid")
        if type(self.config_version) is not str or self.config_version != VIRUSTOTAL_CONFIG_VERSION:
            raise ValueError("virustotal_config_version_invalid")
        bool_fields = (
            "enabled", "submit_high", "submit_malicious", "print_to_cli",
            "print_submitted", "print_skipped", "write_normalized_results",
            "poll_for_report", "wait_for_full_report", "include_full_response",
            "retry_transient_errors",
        )
        for name in bool_fields:
            value = object.__getattribute__(self, name)
            if type(value) is not bool:
                raise TypeError("virustotal_" + name + "_invalid")
        object.__setattr__(self, "api_key_environment_variable", _exact_env_name(self.api_key_environment_variable))
        object.__setattr__(self, "poll_interval_sec", _bounded_float(self.poll_interval_sec, "virustotal_poll_interval_invalid", 0.1, 3600.0))
        object.__setattr__(self, "poll_attempts", _bounded_int(self.poll_attempts, "virustotal_poll_attempts_invalid", 1, 10000))
        object.__setattr__(self, "poll_max_wait_sec", _bounded_float(self.poll_max_wait_sec, "virustotal_poll_max_wait_invalid", 0.0, 86_400.0))
        object.__setattr__(self, "poll_stable_checks", _bounded_int(self.poll_stable_checks, "virustotal_poll_stable_checks_invalid", 1, 100))
        object.__setattr__(self, "timeout_sec", _bounded_float(self.timeout_sec, "virustotal_timeout_invalid", 0.5, 3600.0))
        object.__setattr__(self, "max_upload_mb", _bounded_float(self.max_upload_mb, "virustotal_max_upload_invalid", 0.001, 1024.0))
        object.__setattr__(self, "network_check_timeout_sec", _bounded_float(self.network_check_timeout_sec, "virustotal_network_timeout_invalid", 0.1, 120.0))
        object.__setattr__(self, "upload_rate_limit_per_minute", _bounded_int(self.upload_rate_limit_per_minute, "virustotal_rate_limit_invalid", 1, 10_000))
        object.__setattr__(self, "daily_upload_limit", _bounded_int(self.daily_upload_limit, "virustotal_daily_limit_invalid", 1, 10_000_000))
        object.__setattr__(self, "max_retries", _bounded_int(self.max_retries, "virustotal_max_retries_invalid", 1, 100))
        object.__setattr__(self, "retry_delay_seconds", _bounded_float(self.retry_delay_seconds, "virustotal_retry_delay_invalid", 0.0, 3600.0))
        if type(self.rate_limit_action) is not str or self.rate_limit_action not in _RATE_LIMIT_ACTIONS:
            raise ValueError("virustotal_rate_limit_action_invalid")

    def semantic_digest(self) -> str:
        payload = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


def config_toml(config: VirusTotalConfig | None = None) -> str:
    owner = VirusTotalConfig() if config is None else config
    if type(owner) is not VirusTotalConfig:
        raise TypeError("virustotal_config_toml_owner_invalid")
    values = asdict(owner)
    lines: list[str] = []
    for name in VirusTotalConfig.__dataclass_fields__:
        value = values[name]
        if type(value) is str:
            lines.append(name + " = " + json.dumps(value, ensure_ascii=True))
        elif type(value) is bool:
            lines.append(name + " = " + str(value).lower())
        elif type(value) in (int, float):
            lines.append(name + " = " + repr(value))
        else:
            raise TypeError("virustotal_config_value_invalid")
    return "\n".join(lines) + "\n"


def config_schema_json() -> str:
    properties: dict[str, object] = {
        "config_version": {"const": VIRUSTOTAL_CONFIG_VERSION},
        "enabled": {"type": "boolean"},
        "api_key_environment_variable": {"pattern": _ENV_NAME.pattern, "type": "string"},
        "submit_high": {"type": "boolean"},
        "submit_malicious": {"type": "boolean"},
        "print_to_cli": {"type": "boolean"},
        "print_submitted": {"type": "boolean"},
        "print_skipped": {"type": "boolean"},
        "write_normalized_results": {"type": "boolean"},
        "poll_for_report": {"type": "boolean"},
        "wait_for_full_report": {"type": "boolean"},
        "poll_interval_sec": {"minimum": 0.1, "maximum": 3600.0, "type": "number"},
        "poll_attempts": {"minimum": 1, "maximum": 10000, "type": "integer"},
        "poll_max_wait_sec": {"minimum": 0.0, "maximum": 86400.0, "type": "number"},
        "poll_stable_checks": {"minimum": 1, "maximum": 100, "type": "integer"},
        "timeout_sec": {"minimum": 0.5, "maximum": 3600.0, "type": "number"},
        "max_upload_mb": {"minimum": 0.001, "maximum": 1024.0, "type": "number"},
        "include_full_response": {"type": "boolean"},
        "network_check_timeout_sec": {"minimum": 0.1, "maximum": 120.0, "type": "number"},
        "upload_rate_limit_per_minute": {"minimum": 1, "maximum": 10000, "type": "integer"},
        "daily_upload_limit": {"minimum": 1, "maximum": 10000000, "type": "integer"},
        "rate_limit_action": {"enum": sorted(_RATE_LIMIT_ACTIONS)},
        "retry_transient_errors": {"type": "boolean"},
        "max_retries": {"minimum": 1, "maximum": 100, "type": "integer"},
        "retry_delay_seconds": {"minimum": 0.0, "maximum": 3600.0, "type": "number"},
    }
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": properties,
        "required": sorted(properties),
        "title": "UMIGE VirusTotal configuration",
        "type": "object",
    }
    return json.dumps(schema, sort_keys=True, indent=2, allow_nan=False) + "\n"


def config_readme() -> str:
    return (
        "UMIGE VirusTotal configuration\n\n"
        "VirusTotal/virustotal_config.toml is generated when missing, schema-validated, and loaded automatically.\n"
        "The generated and code-owned default is enabled = false. Disabled VirusTotal performs no connectivity probe or credential resolution.\n"
        "When enabled = true, one bounded probe to the code-owned VirusTotal service target runs before credential/runtime-prerequisite validation.\n"
        "An offline result is session-scoped network_unavailable and never rewrites the persisted enabled request.\n"
        "The editable configuration stores only the environment-variable name used to obtain the API key; no connectivity bypass or endpoint override exists.\n"
        "The API key itself is never written to configuration, logs, reports, manifests, tests, or packages.\n"
        "Official VirusTotal API endpoints and probe target are owned by the canonical client and are not configurable.\n"
        "Every VirusTotal state is external corroboration only and never changes local evidence, score, verdict, Tags, Chains, MITRE, or learning.\n"
    )


def _read_config_text(path: Path) -> str:
    try:
        initial = path.lstat()
    except OSError as exc:
        raise ValueError("virustotal_config_file_invalid") from exc
    if (
        path_contains_filesystem_alias(path)
        or stat_result_is_filesystem_alias(initial)
        or not stat.S_ISREG(initial.st_mode)
        or initial.st_size > _MAX_CONFIG_BYTES
    ):
        raise ValueError("virustotal_config_file_invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError("virustotal_config_file_invalid") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino):
            raise ValueError("virustotal_config_file_invalid")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(_MAX_CONFIG_BYTES + 1)
        if len(data) > _MAX_CONFIG_BYTES:
            raise ValueError("virustotal_config_file_invalid")
    finally:
        os.close(descriptor)
    try:
        final = path.lstat()
    except OSError as exc:
        raise ValueError("virustotal_config_file_invalid") from exc
    if (
        path_contains_filesystem_alias(path)
        or stat_result_is_filesystem_alias(final)
        or not stat.S_ISREG(final.st_mode)
        or (final.st_dev, final.st_ino) != (initial.st_dev, initial.st_ino)
    ):
        raise ValueError("virustotal_config_file_invalid")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("virustotal_config_file_invalid") from exc


def load_config(path: Path) -> VirusTotalConfig:
    if type(path) not in _PATH_TYPES:
        raise ValueError("virustotal_config_file_invalid")
    try:
        raw = tomllib.loads(_read_config_text(path))
    except tomllib.TOMLDecodeError as exc:
        raise ValueError("virustotal_config_toml_invalid") from exc
    expected = set(VirusTotalConfig.__dataclass_fields__)
    if type(raw) is not dict or set(raw) != expected:
        raise ValueError("virustotal_config_fields_rejected")
    values = {name: dict.get(raw, name) for name in VirusTotalConfig.__dataclass_fields__}
    return VirusTotalConfig(**values)


__all__ = (
    "VIRUSTOTAL_CONFIG_VERSION",
    "VirusTotalConfig",
    "config_readme",
    "config_schema_json",
    "config_toml",
    "load_config",
)
