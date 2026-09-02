"""Typed runtime configuration owned by explicit scan/runtime contexts.

Configuration objects expose deterministic mappings for the caller that owns
process environment publication.  The dataclasses themselves do not mutate
module or process globals.
"""
from __future__ import annotations
from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS
from Virus_Scan.contracts.env_config import float_env, int_env
from Virus_Scan.runtime.resource_economics import ResourceEconomicsConfig

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from Virus_Scan.runtime.immutable_core import freeze_runtime_value, materialize_runtime_value
from Virus_Scan.contracts.no_hook_materialization import (
    exact_bool_or_none,
    no_hook_failure,
    no_hook_plain_instance_dict,
    no_hook_text,
)



def _owned_runtime_config_types() -> tuple[type[object], ...]:
    return (ArchiveScanLimits, StageConcurrencyLimits, ResourceEconomicsConfig, PersistenceConfig)


def _runtime_config_evidence(reason: str, value: object) -> dict[str, object]:
    evidence = no_hook_failure(reason, value)
    evidence["runtime_config_failure"] = True
    return evidence


def _freeze_runtime_config_value(value: object) -> object:
    """Detach runtime config payloads without retaining unsafe caller objects.

    RuntimeConfig accepts owned frozen config dataclasses as canonical objects.
    Any other direct-constructor payload is frozen through the canonical
    no-hook runtime materializer so hostile objects cannot be retained and later
    traversed by env/as-mapping publication.
    """
    if value is None:
        return None
    if type(value) in _owned_runtime_config_types():
        return value
    return freeze_runtime_value(value)


def _runtime_config_section_mapping(value: object) -> object:
    """Return deterministic JSON-style config materialization with no hooks."""
    if value is None:
        return None
    return materialize_runtime_value(value)


def _config_reason(reason: str, suffix: str) -> str:
    return f"{reason}{suffix}"


def _stage_limit_env_key(key_text: str) -> str:
    return "".join(("UMIGE_STAGE_LIMIT_", str.upper(key_text)))


def _stage_limits_mapping(value: object) -> dict[str, object]:
    mapped = _runtime_config_section_mapping(value)
    if type(mapped) is dict:
        return mapped
    if mapped is None:
        return _runtime_config_evidence("runtime_stage_limits_missing", value)
    return {"value": mapped, "unavailable_reason": "runtime_stage_limits_unavailable", "runtime_config_failure": True}


def _config_text(value: object, default: str, *, reason: str) -> str:
    text, unavailable = no_hook_text(
        value,
        missing_reason=_config_reason(reason, "_missing"),
        unsupported_reason=_config_reason(reason, "_unsafe_text_rejected"),
    )
    if unavailable or text == "":
        return default
    return text


def _config_bool(value: object, *, default: bool = False) -> bool:
    flag = exact_bool_or_none(value)
    if flag is None:
        return default
    return flag


def _arg_value(args: object, name: str, default: object) -> object:
    """Read parser-owned namespace fields without descriptors/properties/hooks."""
    if args is None:
        return default
    data = no_hook_plain_instance_dict(args)
    if data is None:
        return default
    return dict.get(data, name, default)


def _env_text(value: object, default: str) -> str:
    text, unavailable = no_hook_text(
        value,
        missing_reason="runtime_env_value_missing",
        unsupported_reason="runtime_env_value_unsafe_text_rejected",
    )
    if unavailable or text == "":
        return default
    return text


@dataclass(frozen=True)
class ArchiveScanLimits:
    """Hard archive expansion quotas used before recursive extraction continues."""

    max_depth: int = 2
    max_members: int = 250
    max_member_size: int = 25 * 1024 * 1024
    max_total_extracted_bytes: int = 128 * 1024 * 1024
    max_total_extracted_files: int = 500
    max_decompression_ratio: float = 120.0

    @classmethod
    def from_env(cls) -> "ArchiveScanLimits":
        return cls(
            max_depth=int_env("UMIGE_ARCHIVE_MAX_DEPTH", cls.max_depth, 0, 16),
            max_members=int_env("UMIGE_ARCHIVE_MAX_MEMBERS", cls.max_members, 1, 100000),
            max_member_size=int_env("UMIGE_ARCHIVE_MAX_MEMBER_SIZE", cls.max_member_size, 1024),
            max_total_extracted_bytes=int_env("UMIGE_ARCHIVE_MAX_TOTAL_BYTES", cls.max_total_extracted_bytes, 1024),
            max_total_extracted_files=int_env("UMIGE_ARCHIVE_MAX_TOTAL_FILES", cls.max_total_extracted_files, 1),
            max_decompression_ratio=float_env("UMIGE_ARCHIVE_MAX_RATIO", cls.max_decompression_ratio, 1.0),
        )

    def env_mapping(self) -> dict[str, str]:
        return {
            "UMIGE_ARCHIVE_MAX_DEPTH": _env_text(self.max_depth, _env_text(type(self).max_depth, "2")),
            "UMIGE_ARCHIVE_MAX_MEMBERS": _env_text(self.max_members, _env_text(type(self).max_members, "250")),
            "UMIGE_ARCHIVE_MAX_MEMBER_SIZE": _env_text(self.max_member_size, _env_text(type(self).max_member_size, "26214400")),
            "UMIGE_ARCHIVE_MAX_TOTAL_BYTES": _env_text(self.max_total_extracted_bytes, _env_text(type(self).max_total_extracted_bytes, "134217728")),
            "UMIGE_ARCHIVE_MAX_TOTAL_FILES": _env_text(self.max_total_extracted_files, _env_text(type(self).max_total_extracted_files, "500")),
            "UMIGE_ARCHIVE_MAX_RATIO": _env_text(self.max_decompression_ratio, _env_text(type(self).max_decompression_ratio, "120.0")),
        }



@dataclass(frozen=True)
class StageConcurrencyLimits:
    """Admission caps for expensive scan stages.

    These values feed the existing scheduler stage semaphore path.  They do not
    alter detection or scoring; they only reduce synchronized heavy-stage bursts.
    """

    archive: int = 2
    dotnet: int = 1
    yara: int = 2
    image: int = 3
    raw: int = 4
    generic: int = 8
    model: int = 2
    reporting: int = 1

    @classmethod
    def from_env(cls) -> "StageConcurrencyLimits":
        return cls(
            archive=int_env("UMIGE_STAGE_LIMIT_ARCHIVE", cls.archive, 1, 128),
            dotnet=int_env("UMIGE_STAGE_LIMIT_DOTNET", cls.dotnet, 1, 128),
            yara=int_env("UMIGE_STAGE_LIMIT_YARA", cls.yara, 1, 128),
            image=int_env("UMIGE_STAGE_LIMIT_IMAGE", cls.image, 1, 128),
            raw=int_env("UMIGE_STAGE_LIMIT_RAW", cls.raw, 1, 256),
            generic=int_env("UMIGE_STAGE_LIMIT_GENERIC", cls.generic, 1, 256),
            model=int_env("UMIGE_STAGE_LIMIT_MODEL", cls.model, 1, 128),
            reporting=int_env("UMIGE_STAGE_LIMIT_REPORTING", cls.reporting, 1, 64),
        )

    def as_dict(self) -> dict[str, int]:
        return {
            "archive": self.archive,
            "dotnet": self.dotnet,
            "yara": self.yara,
            "image": self.image,
            "raw": self.raw,
            "generic": self.generic,
            "model": self.model,
            "reporting": self.reporting,
        }

    def env_mapping(self) -> dict[str, str]:
        values: dict[str, str] = {}
        limits = self.as_dict()
        for key, value in tuple(dict.items(limits)):
            key_text = _config_text(key, "", reason="runtime_stage_limit_key")
            if key_text == "":
                continue
            values[_stage_limit_env_key(key_text)] = _env_text(value, "1")
        return values



@dataclass(frozen=True)
class PersistenceConfig:
    """Resolved canonical Scan Logs generation paths for one scan run."""

    scan_log_root: str
    scan_id: str
    staging_path: str
    run_path: str
    output_path: str
    scanlog_path: str | None
    preserve_scan_results: bool = False

    @classmethod
    def from_args(cls, args: object) -> "PersistenceConfig":
        scan_log_root = _config_text(
            _arg_value(args, "scan_log_root", ""),
            "",
            reason="runtime_scan_log_root",
        )
        scan_id = _config_text(
            _arg_value(args, "scan_id", ""),
            "",
            reason="runtime_scan_id",
        )
        staging_path = _config_text(
            _arg_value(args, "scan_log_staging_path", ""),
            "",
            reason="runtime_scan_log_staging_path",
        )
        run_path = _config_text(
            _arg_value(args, "scan_log_run_path", ""),
            "",
            reason="runtime_scan_log_run_path",
        )
        output = _config_text(
            _arg_value(args, "output", ""),
            "",
            reason="runtime_output_path",
        )
        log_value = _arg_value(args, "log", None)
        scanlog = None if log_value is None else _config_text(
            log_value,
            "",
            reason="runtime_scanlog_path",
        )
        required = (scan_log_root, scan_id, staging_path, run_path, output)
        if any(value == "" for value in required):
            raise ValueError("runtime_scan_log_output_plan_missing")
        return cls(
            scan_log_root=scan_log_root,
            scan_id=scan_id,
            staging_path=staging_path,
            run_path=run_path,
            output_path=output,
            scanlog_path=scanlog,
            preserve_scan_results=_config_bool(_arg_value(args, "preserve_scan_results", default=False)),
        )



@dataclass(frozen=True)
class RuntimeConfig:
    archive_limits: ArchiveScanLimits
    stage_limits: StageConcurrencyLimits
    economics: object | None = None
    persistence: PersistenceConfig | Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        """Freeze direct-constructor runtime config payloads.

        The runtime config object crosses scheduler/scanner/orchestration
        boundaries as a snapshot.  Direct construction with dictionaries must
        not preserve caller-owned mutable economics or persistence payloads.
        """
        if type(self) is not RuntimeConfig:
            exception_message = "runtime config owner rejected"
            raise TypeError(exception_message)
        object.__setattr__(self, "archive_limits", _freeze_runtime_config_value(self.archive_limits))
        object.__setattr__(self, "stage_limits", _freeze_runtime_config_value(self.stage_limits))
        object.__setattr__(self, "economics", _freeze_runtime_config_value(self.economics))
        object.__setattr__(self, "persistence", _freeze_runtime_config_value(self.persistence))

    @classmethod
    def from_args(cls, args: object | None = None) -> "RuntimeConfig":
        return cls(
            archive_limits=ArchiveScanLimits.from_env(),
            stage_limits=StageConcurrencyLimits.from_env(),
            economics=ResourceEconomicsConfig.from_env(),
            persistence=PersistenceConfig.from_args(args) if args is not None else None,
        )

    def env_mapping(self) -> dict[str, str]:
        values: dict[str, str] = {}
        if type(self.archive_limits) is ArchiveScanLimits:
            values.update(self.archive_limits.env_mapping())
        if type(self.stage_limits) is StageConcurrencyLimits:
            values.update(self.stage_limits.env_mapping())
        if type(self.economics) is ResourceEconomicsConfig:
            values.update(self.economics.env_mapping())
        return values

    def as_mapping(self) -> dict[str, object]:
        return {
            "archive_limits": _runtime_config_section_mapping(self.archive_limits),
            "stage_limits": _stage_limits_mapping(self.stage_limits),
            "economics": _runtime_config_section_mapping(self.economics),
            "persistence": _runtime_config_section_mapping(self.persistence),
        }

    def as_checkpoint_fact(self) -> dict[str, object]:
        payload = self.as_mapping()
        return {
            "kind": "configuration_checkpoint",
            "schema": "runtime_config_v1",
            "sections": sorted(dict.keys(payload)),
            "payload": payload,
        }
