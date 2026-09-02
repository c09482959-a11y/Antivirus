"""Policy loaders for payload, pickle, raw chunk, text, filetype, and engine config."""
from __future__ import annotations

import json
from pathlib import Path

from Virus_Scan.scanners.config.contracts import (
    EnginePolicySnapshot,
    FiletypePolicySnapshot,
    PayloadPolicySnapshot,
    PicklePolicySnapshot,
    RawChunkPolicySnapshot,
    ScannerConfigError,
    ScannerConfigFailure,
    TextPolicySnapshot,
)
from Virus_Scan.scanners.config.loader_paths import (
    _config_source_text,
    _DEFAULT_ENGINE_POLICY,
    _DEFAULT_FILETYPE_POLICY,
    _DEFAULT_PAYLOAD_POLICY,
    _DEFAULT_PICKLE_POLICY,
    _DEFAULT_RAW_CHUNK_POLICY,
    _DEFAULT_TEXT_POLICY,
    _config_load_failure,
    _load_json,
)
from Virus_Scan.scanners.config.loader_results import (
    EnginePolicyLoadResult,
    FiletypePolicyLoadResult,
    PayloadPolicyLoadResult,
    PicklePolicyLoadResult,
    RawChunkPolicyLoadResult,
    TextPolicyLoadResult,
)
from Virus_Scan.scanners.config.validation import (
    validate_engine_policy,
    validate_filetype_policy,
    validate_payload_policy,
    validate_pickle_policy,
    validate_raw_chunk_policy,
    validate_text_policy,
)
from Virus_Scan.scanners.contracts import scanner_failure_evidence_record, scanner_contract_error_message

def load_payload_policy_result(path: str | Path | None = None) -> PayloadPolicyLoadResult:
    source = Path(path) if path is not None else _DEFAULT_PAYLOAD_POLICY
    try:
        snapshot = validate_payload_policy(_load_json(source), source=_config_source_text(source))
        return PayloadPolicyLoadResult(snapshot=snapshot)
    except ScannerConfigError as exc:
        return PayloadPolicyLoadResult(snapshot=None, failure=exc.failure)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        evidence = scanner_failure_evidence_record(
            "scanner_config",
            "payload_policy",
            exc,
            state="failure",
            error_category="scanner_config_load_failure",
            error_source="scanner_config.payload_policy_loader",
            policy_config_source=_config_source_text(source),
        )
        failure = ScannerConfigFailure("payload_policy", _config_source_text(source), scanner_contract_error_message(exc), (evidence,))
        return PayloadPolicyLoadResult(snapshot=None, failure=failure)

def load_payload_policy_snapshot(path: str | Path | None = None) -> PayloadPolicySnapshot:
    result = load_payload_policy_result(path)
    if result.snapshot is None or result.failure is not None:
        raise ScannerConfigError(result.failure or ScannerConfigFailure("payload_policy", _config_source_text(path if path is not None else _DEFAULT_PAYLOAD_POLICY), "unknown payload policy failure"))
    return result.snapshot

def load_pickle_policy_result(path: str | Path | None = None) -> PicklePolicyLoadResult:
    source = Path(path) if path is not None else _DEFAULT_PICKLE_POLICY
    try:
        snapshot = validate_pickle_policy(_load_json(source), source=_config_source_text(source))
        return PicklePolicyLoadResult(snapshot=snapshot)
    except ScannerConfigError as exc:
        return PicklePolicyLoadResult(snapshot=None, failure=exc.failure)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return PicklePolicyLoadResult(snapshot=None, failure=_config_load_failure("pickle_policy", source, exc))

def load_pickle_policy_snapshot(path: str | Path | None = None) -> PicklePolicySnapshot:
    result = load_pickle_policy_result(path)
    if result.snapshot is None or result.failure is not None:
        raise ScannerConfigError(result.failure or ScannerConfigFailure("pickle_policy", _config_source_text(path if path is not None else _DEFAULT_PICKLE_POLICY), "unknown pickle policy failure"))
    return result.snapshot

def load_raw_chunk_policy_result(path: str | Path | None = None) -> RawChunkPolicyLoadResult:
    source = Path(path) if path is not None else _DEFAULT_RAW_CHUNK_POLICY
    try:
        snapshot = validate_raw_chunk_policy(_load_json(source), source=_config_source_text(source))
        return RawChunkPolicyLoadResult(snapshot=snapshot)
    except ScannerConfigError as exc:
        return RawChunkPolicyLoadResult(snapshot=None, failure=exc.failure)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return RawChunkPolicyLoadResult(snapshot=None, failure=_config_load_failure("raw_chunk_policy", source, exc))

def load_raw_chunk_policy_snapshot(path: str | Path | None = None) -> RawChunkPolicySnapshot:
    result = load_raw_chunk_policy_result(path)
    if result.snapshot is None or result.failure is not None:
        raise ScannerConfigError(result.failure or ScannerConfigFailure("raw_chunk_policy", _config_source_text(path if path is not None else _DEFAULT_RAW_CHUNK_POLICY), "unknown raw chunk policy failure"))
    return result.snapshot

def load_text_policy_result(path: str | Path | None = None) -> TextPolicyLoadResult:
    source = Path(path) if path is not None else _DEFAULT_TEXT_POLICY
    try:
        snapshot = validate_text_policy(_load_json(source), source=_config_source_text(source))
        return TextPolicyLoadResult(snapshot=snapshot)
    except ScannerConfigError as exc:
        return TextPolicyLoadResult(snapshot=None, failure=exc.failure)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return TextPolicyLoadResult(snapshot=None, failure=_config_load_failure("text_policy", source, exc))

def load_text_policy_snapshot(path: str | Path | None = None) -> TextPolicySnapshot:
    result = load_text_policy_result(path)
    if result.snapshot is None or result.failure is not None:
        raise ScannerConfigError(result.failure or ScannerConfigFailure("text_policy", _config_source_text(path if path is not None else _DEFAULT_TEXT_POLICY), "unknown text policy failure"))
    return result.snapshot

def load_filetype_policy_result(path: str | Path | None = None) -> FiletypePolicyLoadResult:
    source = Path(path) if path is not None else _DEFAULT_FILETYPE_POLICY
    try:
        snapshot = validate_filetype_policy(_load_json(source), source=_config_source_text(source))
        return FiletypePolicyLoadResult(snapshot=snapshot)
    except ScannerConfigError as exc:
        return FiletypePolicyLoadResult(snapshot=None, failure=exc.failure)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return FiletypePolicyLoadResult(snapshot=None, failure=_config_load_failure("filetype_policy", source, exc))

def load_filetype_policy_snapshot(path: str | Path | None = None) -> FiletypePolicySnapshot:
    result = load_filetype_policy_result(path)
    if result.snapshot is None or result.failure is not None:
        raise ScannerConfigError(result.failure or ScannerConfigFailure("filetype_policy", _config_source_text(path if path is not None else _DEFAULT_FILETYPE_POLICY), "unknown filetype policy failure"))
    return result.snapshot

def load_engine_policy_result(path: str | Path | None = None) -> EnginePolicyLoadResult:
    source = Path(path) if path is not None else _DEFAULT_ENGINE_POLICY
    try:
        snapshot = validate_engine_policy(_load_json(source), source=_config_source_text(source))
        return EnginePolicyLoadResult(snapshot=snapshot)
    except ScannerConfigError as exc:
        return EnginePolicyLoadResult(snapshot=None, failure=exc.failure)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return EnginePolicyLoadResult(snapshot=None, failure=_config_load_failure("engine_policy", source, exc))

def load_engine_policy_snapshot(path: str | Path | None = None) -> EnginePolicySnapshot:
    result = load_engine_policy_result(path)
    if result.snapshot is None or result.failure is not None:
        raise ScannerConfigError(result.failure or ScannerConfigFailure("engine_policy", _config_source_text(path if path is not None else _DEFAULT_ENGINE_POLICY), "unknown engine policy failure"))
    return result.snapshot

__all__ = (
    "load_engine_policy_result",
    "load_engine_policy_snapshot",
    "load_filetype_policy_result",
    "load_filetype_policy_snapshot",
    "load_payload_policy_result",
    "load_payload_policy_snapshot",
    "load_pickle_policy_result",
    "load_pickle_policy_snapshot",
    "load_raw_chunk_policy_result",
    "load_raw_chunk_policy_snapshot",
    "load_text_policy_result",
    "load_text_policy_snapshot",
)
