"""Immutable configuration and deterministic generated controls for ATT&CK."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path, PosixPath, WindowsPath
import tomllib

_PATH_TYPES = (Path, PosixPath, WindowsPath)

from Virus_Scan.detection.attack.validation import (
    ATTACK_GIT_REF_PATTERN_TEXT, exact_bool, exact_git_ref, exact_https_endpoint,
)
from Virus_Scan.detection.attack.versioning import ATTACK_CONFIG_VERSION

DEFAULT_API_URL = "https://api.github.com/repos/mitre-attack/attack-stix-data/contents/enterprise-attack/enterprise-attack.json"
DEFAULT_REF = "master"
DEFAULT_MAX_BYTES = 256 * 1024 * 1024
_MAX_CONFIG_BYTES = 64 * 1024
_ALLOWED_API_PATH = "/repos/mitre-attack/attack-stix-data/contents/enterprise-attack/enterprise-attack.json"


@dataclass(frozen=True, slots=True)
class AttackConfig:
    enabled: bool = True
    allow_download: bool = False
    force_refresh: bool = False
    api_url: str = DEFAULT_API_URL
    ref: str = DEFAULT_REF
    maximum_bytes: int = DEFAULT_MAX_BYTES

    def __post_init__(self) -> None:
        if type(self) is not AttackConfig:
            raise TypeError("attack_config_owner_invalid")
        object.__setattr__(self, "enabled", exact_bool(self.enabled, "attack_config_enabled_invalid"))
        object.__setattr__(self, "allow_download", exact_bool(self.allow_download, "attack_config_download_invalid"))
        object.__setattr__(self, "force_refresh", exact_bool(self.force_refresh, "attack_config_refresh_invalid"))
        api_url, _parsed = exact_https_endpoint(
            self.api_url, "attack_config_api_identity_rejected",
            hostname="api.github.com", path=_ALLOWED_API_PATH, maximum=2048,
        )
        object.__setattr__(self, "api_url", api_url)
        object.__setattr__(self, "ref", exact_git_ref(self.ref, "attack_config_ref_invalid"))
        if type(self.maximum_bytes) is not int or type(self.maximum_bytes) is bool or not 1024 <= self.maximum_bytes <= DEFAULT_MAX_BYTES:
            raise ValueError("attack_config_maximum_bytes_invalid")

    def to_record(self) -> dict[str, object]:
        return {
            "config_version": ATTACK_CONFIG_VERSION,
            "enabled": self.enabled,
            "allow_download": self.allow_download,
            "force_refresh": self.force_refresh,
            "api_url": self.api_url,
            "ref": self.ref,
            "maximum_bytes": self.maximum_bytes,
        }


def config_toml() -> str:
    return (
        f'config_version = "{ATTACK_CONFIG_VERSION}"\n'
        "enabled = true\n"
        "allow_download = false\n"
        "force_refresh = false\n"
        f'api_url = "{DEFAULT_API_URL}"\n'
        f'ref = "{DEFAULT_REF}"\n'
        f"maximum_bytes = {DEFAULT_MAX_BYTES}\n"
    )


def config_schema_json() -> str:
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": {
            "allow_download": {"type": "boolean"},
            "api_url": {"const": DEFAULT_API_URL},
            "config_version": {"const": ATTACK_CONFIG_VERSION},
            "enabled": {"type": "boolean"},
            "force_refresh": {"type": "boolean"},
            "maximum_bytes": {"maximum": DEFAULT_MAX_BYTES, "minimum": 1024, "type": "integer"},
            "ref": {"maxLength": 128, "minLength": 1, "pattern": ATTACK_GIT_REF_PATTERN_TEXT, "type": "string"},
        },
        "required": sorted({
            "config_version", "enabled", "allow_download", "force_refresh",
            "api_url", "ref", "maximum_bytes",
        }),
        "title": "UMIGE Enterprise ATT&CK configuration",
        "type": "object",
    }
    return json.dumps(schema, sort_keys=True, indent=2) + "\n"


def config_readme() -> str:
    return (
        "UMIGE Enterprise ATT&CK configuration\n"
        "\n"
        "MITRE/ATT&CK is enabled by canonical typed application defaults during normal startup.\n"
        "Mitre/mitre_config.toml is an editable explicit override and is not read unless --mitre-config is supplied.\n"
        "Mitre/mitre_defaults.toml is a generated human-readable projection only and is never a runtime configuration source.\n"
        "The packaged Mitre/enterprise-attack.json seed is discovered independently through ResourceRootSnapshot.\n"
        "allow_download is false by default. Per-file scans never access the network.\n"
        "The GitHub Contents API sha is the trusted Git-blob identity for an explicitly authorized refresh.\n"
        "Existing generated controls are never overwritten during ordinary startup.\n"
    )


def load_config(path: Path) -> AttackConfig:
    if type(path) not in _PATH_TYPES:
        raise TypeError("attack_config_path_required")
    if not path.is_file() or path.stat().st_size > _MAX_CONFIG_BYTES:
        raise ValueError("attack_config_file_invalid")
    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    if type(raw) is not dict or dict.get(raw, "config_version") != ATTACK_CONFIG_VERSION:
        raise ValueError("attack_config_version_rejected")
    allowed = {
        "config_version", "enabled", "allow_download", "force_refresh",
        "api_url", "ref", "maximum_bytes",
    }
    if set(raw) != allowed:
        raise ValueError("attack_config_fields_rejected")
    return AttackConfig(
        enabled=dict.get(raw, "enabled"),
        allow_download=dict.get(raw, "allow_download"),
        force_refresh=dict.get(raw, "force_refresh"),
        api_url=dict.get(raw, "api_url"),
        ref=dict.get(raw, "ref"),
        maximum_bytes=dict.get(raw, "maximum_bytes"),
    )


__all__ = (
    "AttackConfig", "DEFAULT_API_URL", "DEFAULT_MAX_BYTES", "DEFAULT_REF",
    "config_readme", "config_schema_json", "config_toml", "load_config",
)
