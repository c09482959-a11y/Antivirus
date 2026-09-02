"""Policy loaders for binary, archive/RPA, and scanner-limit config."""
from __future__ import annotations

import json
from pathlib import Path

from Virus_Scan.scanners.config.contracts import (
    ArchivePolicySnapshot,
    BinaryPolicySnapshot,
    ScannerConfigError,
    ScannerConfigFailure,
    ScannerLimitsPolicySnapshot,
)
from Virus_Scan.scanners.config.loader_paths import (
    _DEFAULT_ARCHIVE_POLICY,
    _DEFAULT_BINARY_POLICY,
    _DEFAULT_SCANNER_LIMITS_POLICY,
    _config_load_failure,
    _config_source_text,
    _load_json,
)
from Virus_Scan.scanners.config.loader_results import (
    ArchivePolicyLoadResult,
    BinaryPolicyLoadResult,
    ScannerLimitsPolicyLoadResult,
)
from Virus_Scan.scanners.config.validation import (
    validate_archive_policy,
    validate_binary_policy,
    validate_scanner_limits_policy,
)

def load_binary_policy_result(path: str | Path | None = None) -> BinaryPolicyLoadResult:
    source = Path(path) if path is not None else _DEFAULT_BINARY_POLICY
    try:
        snapshot = validate_binary_policy(_load_json(source), source=_config_source_text(source))
        return BinaryPolicyLoadResult(snapshot=snapshot)
    except ScannerConfigError as exc:
        return BinaryPolicyLoadResult(snapshot=None, failure=exc.failure)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return BinaryPolicyLoadResult(snapshot=None, failure=_config_load_failure("binary_policy", source, exc))

def load_binary_policy_snapshot(path: str | Path | None = None) -> BinaryPolicySnapshot:
    result = load_binary_policy_result(path)
    if result.snapshot is None or result.failure is not None:
        raise ScannerConfigError(result.failure or ScannerConfigFailure("binary_policy", _config_source_text(path if path is not None else _DEFAULT_BINARY_POLICY), "unknown binary policy failure"))
    return result.snapshot

def load_archive_policy_result(path: str | Path | None = None) -> ArchivePolicyLoadResult:
    source = Path(path) if path is not None else _DEFAULT_ARCHIVE_POLICY
    try:
        snapshot = validate_archive_policy(_load_json(source), source=_config_source_text(source))
        return ArchivePolicyLoadResult(snapshot=snapshot)
    except ScannerConfigError as exc:
        return ArchivePolicyLoadResult(snapshot=None, failure=exc.failure)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return ArchivePolicyLoadResult(snapshot=None, failure=_config_load_failure("archive_policy", source, exc))

def load_archive_policy_snapshot(path: str | Path | None = None) -> ArchivePolicySnapshot:
    result = load_archive_policy_result(path)
    if result.snapshot is None or result.failure is not None:
        raise ScannerConfigError(result.failure or ScannerConfigFailure("archive_policy", _config_source_text(path if path is not None else _DEFAULT_ARCHIVE_POLICY), "unknown archive policy failure"))
    return result.snapshot

def load_scanner_limits_policy_result(path: str | Path | None = None) -> ScannerLimitsPolicyLoadResult:
    source = Path(path) if path is not None else _DEFAULT_SCANNER_LIMITS_POLICY
    try:
        snapshot = validate_scanner_limits_policy(_load_json(source), source=_config_source_text(source))
        return ScannerLimitsPolicyLoadResult(snapshot=snapshot)
    except ScannerConfigError as exc:
        return ScannerLimitsPolicyLoadResult(snapshot=None, failure=exc.failure)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return ScannerLimitsPolicyLoadResult(snapshot=None, failure=_config_load_failure("scanner_limits_policy", source, exc))

def load_scanner_limits_policy_snapshot(path: str | Path | None = None) -> ScannerLimitsPolicySnapshot:
    result = load_scanner_limits_policy_result(path)
    if result.snapshot is None or result.failure is not None:
        raise ScannerConfigError(result.failure or ScannerConfigFailure("scanner_limits_policy", _config_source_text(path if path is not None else _DEFAULT_SCANNER_LIMITS_POLICY), "unknown scanner limits policy failure"))
    return result.snapshot

__all__ = (
    "load_archive_policy_result",
    "load_archive_policy_snapshot",
    "load_binary_policy_result",
    "load_binary_policy_snapshot",
    "load_scanner_limits_policy_result",
    "load_scanner_limits_policy_snapshot",
)
