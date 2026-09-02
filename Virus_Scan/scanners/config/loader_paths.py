"""Canonical scanner policy/config paths and IO helpers."""
from __future__ import annotations

import json
from pathlib import Path, PurePath
from typing import NoReturn

from Virus_Scan.scanners.contracts import (
    scanner_contract_error_message,
    scanner_contract_join,
    scanner_contract_text,
    scanner_failure_evidence_record,
)
from Virus_Scan.scanners.config.contracts import ScannerConfigFailure

_CONFIG_ROOT = Path(__file__).resolve().parent
_DEFAULT_PAYLOAD_POLICY = _CONFIG_ROOT / "defaults" / "payload_policy.json"
_DEFAULT_PICKLE_POLICY = _CONFIG_ROOT / "defaults" / "pickle_policy.json"
_DEFAULT_RAW_CHUNK_POLICY = _CONFIG_ROOT / "defaults" / "raw_chunk_policy.json"
_DEFAULT_TEXT_POLICY = _CONFIG_ROOT / "defaults" / "text_policy.json"
_DEFAULT_FILETYPE_POLICY = _CONFIG_ROOT / "defaults" / "filetype_policy.json"
_DEFAULT_ENGINE_POLICY = _CONFIG_ROOT / "defaults" / "engine_policy.json"
_DEFAULT_BINARY_POLICY = _CONFIG_ROOT / "defaults" / "binary_policy.json"
_DEFAULT_ARCHIVE_POLICY = _CONFIG_ROOT / "defaults" / "archive_policy.json"
_DEFAULT_SCANNER_LIMITS_POLICY = _CONFIG_ROOT / "defaults" / "scanner_limits_policy.json"
_PAYLOAD_POLICY_JSON_ROOT_REQUIRED = "payload policy JSON root must be an object"


def _raise_payload_policy_json_root_required() -> NoReturn:
    raise TypeError(_PAYLOAD_POLICY_JSON_ROOT_REQUIRED)


def _config_source_text(source: object) -> str:
    if isinstance(source, PurePath):
        return PurePath.__str__(source)
    return scanner_contract_text(source, replacement="unsafe_scanner_config_source")


def _config_error_source(config_name: object) -> str:
    return scanner_contract_join("scanner_config.", scanner_contract_text(config_name, replacement="scanner_config"), "_loader")

def _load_json(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        _raise_payload_policy_json_root_required()
    return data

def _config_load_failure(config_name: str, source: Path, exc: BaseException) -> ScannerConfigFailure:
    evidence = scanner_failure_evidence_record(
        "scanner_config",
        config_name,
        exc,
        state="failure",
        error_category="scanner_config_load_failure",
        error_source=_config_error_source(config_name),
        policy_config_source=_config_source_text(source),
    )
    return ScannerConfigFailure(config_name, _config_source_text(source), scanner_contract_error_message(exc), (evidence,)) 

__all__ = (
    "_DEFAULT_ARCHIVE_POLICY",
    "_DEFAULT_BINARY_POLICY",
    "_DEFAULT_ENGINE_POLICY",
    "_DEFAULT_FILETYPE_POLICY",
    "_DEFAULT_PAYLOAD_POLICY",
    "_DEFAULT_PICKLE_POLICY",
    "_DEFAULT_RAW_CHUNK_POLICY",
    "_DEFAULT_SCANNER_LIMITS_POLICY",
    "_DEFAULT_TEXT_POLICY",
    "_config_error_source",
    "_config_load_failure",
    "_config_source_text",
    "_load_json",
)
