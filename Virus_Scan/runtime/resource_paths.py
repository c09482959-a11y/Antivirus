"""Canonical runtime resource, publication-root, and writable-state ownership.

This module owns startup-safe path resolution for source Python and packaged
executables.  It does not inspect the launch current working directory and it
never treats a Nuitka onefile extraction directory as UMIGE's writable state
root.  Callers must use these functions for Yara, Mitre, VirusTotal, Scan Logs,
Temp, profiles, model state, and tool/output locations instead of deriving paths
from cwd.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import re
import sys
from inspect import getattr_static
from pathlib import Path, PosixPath, PurePath, PurePosixPath, PureWindowsPath, WindowsPath
from typing import TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import no_hook_text


_RESOURCE_PATH_ERRORS = (OSError, RuntimeError, ValueError, TypeError, AttributeError)
_STDLIB_PATH_TYPES = (Path, PosixPath, WindowsPath, PurePosixPath, PureWindowsPath)
__compiled__: object
if TYPE_CHECKING:
    __compiled__ = object()
_COMPILED_PRESENT = "__compiled__" in dir()

RESOURCE_ROOT_SNAPSHOT_SCHEMA_VERSION = "resource_root_snapshot_v1"
SCAN_LOG_OUTPUT_PLAN_SCHEMA_VERSION = "scan_log_output_plan_v1"

RESOURCE_CLASSIFICATION_ROOT = "resource_root"
RESOURCE_CLASSIFICATION_PACKAGE = "immutable_package_resource"
RESOURCE_CLASSIFICATION_RUNTIME_CONTROL = "runtime_generated_control"
RESOURCE_CLASSIFICATION_RUNTIME_CACHE = "runtime_cache"
RESOURCE_CLASSIFICATION_RUNTIME_STATE = "runtime_state"
RESOURCE_CLASSIFICATION_SECRET_REFERENCE = "secret_reference"
RESOURCE_CLASSIFICATION_STAGING_OUTPUT = "staging_output"
RESOURCE_CLASSIFICATION_FINAL_PUBLICATION = "final_publication"
RESOURCE_CLASSIFICATION_UNKNOWN = "unknown"

_RESOURCE_CLASSIFICATIONS = frozenset({
    RESOURCE_CLASSIFICATION_ROOT,
    RESOURCE_CLASSIFICATION_PACKAGE,
    RESOURCE_CLASSIFICATION_RUNTIME_CONTROL,
    RESOURCE_CLASSIFICATION_RUNTIME_CACHE,
    RESOURCE_CLASSIFICATION_RUNTIME_STATE,
    RESOURCE_CLASSIFICATION_SECRET_REFERENCE,
    RESOURCE_CLASSIFICATION_STAGING_OUTPUT,
    RESOURCE_CLASSIFICATION_FINAL_PUBLICATION,
    RESOURCE_CLASSIFICATION_UNKNOWN,
})

_YARA_GENERATED_CONTROL_NAMES = frozenset({
    "README.md", "yara_defaults.toml", "yara_config.toml", "yara_config.schema.json",
})
_YARA_PACKAGE_NAMES = frozenset({
    "yara_resource_manifest.json",
    "yara-forge-rules-core.zip",
    "yara-forge-rules-extended.zip",
})
_MITRE_GENERATED_CONTROL_NAMES = frozenset({
    "README.md", "mitre_defaults.toml", "mitre_config.toml", "mitre_config.schema.json",
})
_MITRE_SEED_NAME = "enterprise-attack.json"
_MITRE_PACKAGE_NAMES = frozenset({"NOTICE.txt", _MITRE_SEED_NAME})
_VIRUSTOTAL_GENERATED_CONTROL_NAMES = frozenset({
    "README.md", "virustotal_defaults.toml", "virustotal_config.toml", "virustotal_config.schema.json",
})
_VIRUSTOTAL_PACKAGE_NAMES = frozenset()
_SCAN_LOG_PACKAGE_NAMES = frozenset({"README.txt"})
_SCAN_LOG_REPORT_FILENAMES = (
    "report_manifest.json",
    "scanlog",
    "scan_results.json",
    "malicious_findings_summary.json",
    "malicious_findings_summary.md",
    "malicious_findings_summary.csv",
    "yara_findings_summary.json",
    "yara_findings_summary.md",
    "yara_findings_summary.csv",
    "mitre_findings_summary.json",
    "mitre_findings_summary.md",
    "mitre_findings_summary.csv",
    "chain_findings_summary.json",
    "chain_findings_summary.md",
    "chain_findings_summary.csv",
    "cluster_findings_summary.json",
    "cluster_findings_summary.md",
    "cluster_findings_summary.csv",
    "virustotal_results.json",
    "virustotal_findings_summary.json",
    "virustotal_findings_summary.md",
    "virustotal_findings_summary.csv",
)
_SCAN_ID_RE = re.compile(r"\A[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?\Z")


def _false_bool() -> bool:
    return bool(0)


def _resource_field_text(field_name: object) -> str:
    if type(field_name) is str:
        return str.__str__(field_name)
    return "resource_path_field"


def _resource_reason(field_name: object, suffix: str) -> str:
    return _resource_field_text(field_name) + "_" + str.__str__(suffix)


def _source_tree_root_error(path: Path) -> str:
    return "Unable to resolve UMIGE source root from " + PurePath.as_posix(path)


def _resource_path_text(
    value: object,
    field_name: str,
    *,
    allow_missing: bool = False,
) -> str | None:
    if value is None and allow_missing:
        return None
    if type(value) is Path:
        return Path.as_posix(value)
    if type(value) is PosixPath:
        return PosixPath.as_posix(value)
    if type(value) is WindowsPath:
        return WindowsPath.as_posix(value)
    if type(value) is PurePosixPath:
        return PurePosixPath.as_posix(value)
    if type(value) is PureWindowsPath:
        return PureWindowsPath.as_posix(value)
    text, reason = no_hook_text(
        value,
        missing_reason=_resource_reason(field_name, "missing"),
        unsupported_reason=_resource_reason(field_name, "rejected"),
    )
    if reason or text == "":
        if allow_missing:
            return None
        raise ValueError(reason or _resource_reason(field_name, "blank"))
    return text


def _looks_like_onefile_extraction(path: Path | str | None) -> bool:
    text = _resource_path_text(
        path, "onefile_extraction_path", allow_missing=True
    )
    if text is None:
        return False
    text = text.replace("\\", "/").lower()
    return "/temp/onefile/" in text


def _dir_from_executable_candidate(raw: object) -> Path | None:
    text = _resource_path_text(
        raw, "executable_candidate", allow_missing=True
    )
    if text is None:
        return None
    candidate = Path(text).expanduser()
    if candidate.name:
        candidate = candidate.resolve()
    if candidate.is_file() or candidate.suffix:
        candidate = candidate.parent
    if candidate.exists() and candidate.is_dir() and not _looks_like_onefile_extraction(candidate):
        return candidate
    return None


def _source_tree_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "Virus_Scan").is_dir():
            return parent
    raise RuntimeError(_source_tree_root_error(here))


def _nuitka_compiled_marker() -> bool:
    if not _COMPILED_PRESENT:
        return _false_bool()
    marker = __compiled__
    if type(marker) is bool:
        return marker
    if type(marker) is int:
        return marker != 0
    return _false_bool()


def _is_packaged_runtime() -> bool:
    frozen = getattr_static(sys, "frozen", False)
    frozen_flag = (
        frozen
        if type(frozen) is bool
        else type(frozen) is int and frozen != 0
    )
    return frozen_flag or _nuitka_compiled_marker()


def program_root() -> Path:
    """Return the scanner/program root used for resources and writable state."""
    for env_name in ("UMIGE_BASE_DIR", "UMIGE_EXE_DIR", "UMIGE_PROGRAM_DIR"):
        raw = os.environ.get(env_name)
        if type(raw) is str and raw != "":
            try:
                candidate = Path(raw).expanduser().resolve()
                if candidate.exists() and candidate.is_dir() and not _looks_like_onefile_extraction(candidate):
                    return candidate
            except _RESOURCE_PATH_ERRORS:
                continue

    executable = getattr_static(sys, "executable", None)
    executable_root = _dir_from_executable_candidate(executable)
    if _is_packaged_runtime() and executable_root is not None:
        return executable_root

    for raw in (sys.argv[0] if sys.argv else None, executable):
        executable_candidate = _dir_from_executable_candidate(raw)
        if executable_candidate is not None:
            if (executable_candidate / "Virus_Scan").is_dir() or (executable_candidate / "build_entry_umige.py").exists():
                return executable_candidate
    return _source_tree_root()


def resource_dir(name: str) -> Path:
    name_text = _resource_path_text(name, "resource_dir_name")
    if name_text is None:
        raise ValueError("resource_dir_name_missing")
    path = program_root() / name_text
    path.mkdir(parents=True, exist_ok=True)
    return path


def temp_dir() -> Path:
    return resource_dir("Temp")


def work_queue_dir() -> Path:
    path = temp_dir() / "work_queue"
    path.mkdir(parents=True, exist_ok=True)
    return path


def scan_logs_dir() -> Path:
    return resource_dir("Scan Logs")


def yara_dir() -> Path:
    return resource_dir("Yara")


def mitre_dir() -> Path:
    return resource_dir("Mitre")


def virustotal_dir() -> Path:
    return resource_dir("VirusTotal")


def _resolved_contract_path(value: object, field_name: str) -> Path:
    text = _resource_path_text(value, field_name)
    if text is None:
        raise ValueError(_resource_reason(field_name, "missing"))
    try:
        return Path(text).expanduser().resolve(strict=False)
    except _RESOURCE_PATH_ERRORS as exc:
        raise ValueError(_resource_reason(field_name, "invalid")) from exc


def _relative_to_root(candidate: Path, root: Path) -> tuple[str, ...] | None:
    try:
        return tuple(candidate.relative_to(root).parts)
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class ResourceRootSnapshot:
    """One immutable startup snapshot of every governed top-level root."""

    program_root: str
    yara_root: str
    mitre_root: str
    mitre_seed_path: str
    virustotal_root: str
    scan_logs_root: str
    schema_version: str = RESOURCE_ROOT_SNAPSHOT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not ResourceRootSnapshot:
            raise TypeError("resource_root_snapshot_owner_rejected")
        if type(self.schema_version) is not str:
            raise TypeError("resource_root_snapshot_schema_required")
        if self.schema_version != RESOURCE_ROOT_SNAPSHOT_SCHEMA_VERSION:
            raise ValueError("resource_root_snapshot_schema_invalid")
        resolved_program = _resolved_contract_path(self.program_root, "program_root")
        owned_roots = (
            ("yara_root", self.yara_root, "Yara"),
            ("mitre_root", self.mitre_root, "Mitre"),
            ("virustotal_root", self.virustotal_root, "VirusTotal"),
            ("scan_logs_root", self.scan_logs_root, "Scan Logs"),
        )
        normalized: dict[str, str] = {"program_root": resolved_program.as_posix()}
        for field_name, raw, expected_name in owned_roots:
            resolved = _resolved_contract_path(raw, field_name)
            if resolved.parent != resolved_program or resolved.name != expected_name:
                raise ValueError("resource_root_snapshot_path_invalid:" + field_name)
            normalized[field_name] = resolved.as_posix()
        expected_seed = Path(normalized["mitre_root"]) / _MITRE_SEED_NAME
        resolved_seed = _resolved_contract_path(self.mitre_seed_path, "mitre_seed_path")
        if resolved_seed != expected_seed:
            raise ValueError("resource_root_snapshot_path_invalid:mitre_seed_path")
        normalized["mitre_seed_path"] = resolved_seed.as_posix()
        for field_name, value in normalized.items():
            object.__setattr__(self, field_name, value)

    @property
    def semantic_digest(self) -> str:
        payload = "\n".join((
            self.schema_version,
            self.program_root,
            self.yara_root,
            self.mitre_root,
            self.mitre_seed_path,
            self.virustotal_root,
            self.scan_logs_root,
            ",".join(sorted(_RESOURCE_CLASSIFICATIONS)),
        ))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def classify(self, path: object) -> str:
        """Classify one path without creating a second resource-policy owner."""
        candidate = _resolved_contract_path(path, "resource_classification_path")
        roots = (
            (Path(self.yara_root), "yara"),
            (Path(self.mitre_root), "mitre"),
            (Path(self.virustotal_root), "virustotal"),
            (Path(self.scan_logs_root), "scan_logs"),
        )
        for root, kind in roots:
            relative = _relative_to_root(candidate, root)
            if relative is None:
                continue
            if not relative:
                return RESOURCE_CLASSIFICATION_ROOT
            first = relative[0]
            if kind == "yara":
                if len(relative) == 1 and first in _YARA_GENERATED_CONTROL_NAMES:
                    return RESOURCE_CLASSIFICATION_RUNTIME_CONTROL
                if len(relative) == 1 and first in _YARA_PACKAGE_NAMES:
                    return RESOURCE_CLASSIFICATION_PACKAGE
                if first == ".umige-yara.lock":
                    return RESOURCE_CLASSIFICATION_RUNTIME_CONTROL
                if first in {"yara.cache", "yaralight.cache"}:
                    return RESOURCE_CLASSIFICATION_RUNTIME_CACHE
                if first == "state":
                    return RESOURCE_CLASSIFICATION_RUNTIME_STATE
            elif kind == "mitre":
                if len(relative) == 1 and first in _MITRE_GENERATED_CONTROL_NAMES:
                    return RESOURCE_CLASSIFICATION_RUNTIME_CONTROL
                if len(relative) == 1 and first in _MITRE_PACKAGE_NAMES:
                    return RESOURCE_CLASSIFICATION_PACKAGE
                if first == ".umige-mitre.lock":
                    return RESOURCE_CLASSIFICATION_RUNTIME_CONTROL
                if first == "state" or first.endswith(".index"):
                    return RESOURCE_CLASSIFICATION_RUNTIME_STATE
            elif kind == "virustotal":
                if len(relative) == 1 and first in _VIRUSTOTAL_GENERATED_CONTROL_NAMES:
                    return RESOURCE_CLASSIFICATION_RUNTIME_CONTROL
                if len(relative) == 1 and first in _VIRUSTOTAL_PACKAGE_NAMES:
                    return RESOURCE_CLASSIFICATION_PACKAGE
                if first == ".umige-virustotal.lock":
                    return RESOURCE_CLASSIFICATION_RUNTIME_CONTROL
                if first in {"api_key", "secret", "secrets"}:
                    return RESOURCE_CLASSIFICATION_SECRET_REFERENCE
            elif kind == "scan_logs":
                if len(relative) == 1 and first in _SCAN_LOG_PACKAGE_NAMES:
                    return RESOURCE_CLASSIFICATION_PACKAGE
                if first == ".staging":
                    return RESOURCE_CLASSIFICATION_STAGING_OUTPUT
                if first == "runs" or first == "latest.json":
                    return RESOURCE_CLASSIFICATION_FINAL_PUBLICATION
            return RESOURCE_CLASSIFICATION_UNKNOWN
        return RESOURCE_CLASSIFICATION_UNKNOWN

    def governed_roots(self) -> tuple[tuple[str, str], ...]:
        """Return the exact governed root names and normalized paths."""
        return (
            ("Yara", self.yara_root),
            ("Mitre", self.mitre_root),
            ("VirusTotal", self.virustotal_root),
            ("Scan Logs", self.scan_logs_root),
        )

    def immutable_package_resources(self) -> tuple[tuple[str, str], ...]:
        """Return every immutable package resource from the canonical owner."""
        package_names = {
            "Yara": _YARA_PACKAGE_NAMES,
            "Mitre": _MITRE_PACKAGE_NAMES,
            "VirusTotal": _VIRUSTOTAL_PACKAGE_NAMES,
            "Scan Logs": _SCAN_LOG_PACKAGE_NAMES,
        }
        records: list[tuple[str, str]] = []
        for root_name, root_path in self.governed_roots():
            names = package_names[root_name]
            root = Path(root_path)
            records.extend(
                (root_name, (root / filename).as_posix())
                for filename in sorted(names)
            )
        return tuple(records)

    def generated_control_resources(self) -> tuple[tuple[str, str], ...]:
        """Return the exact generated controls that standalone packaging must carry."""
        control_names = {
            "Yara": _YARA_GENERATED_CONTROL_NAMES,
            "Mitre": _MITRE_GENERATED_CONTROL_NAMES,
            "VirusTotal": _VIRUSTOTAL_GENERATED_CONTROL_NAMES,
        }
        roots = dict(self.governed_roots())
        records: list[tuple[str, str]] = []
        for root_name in ("Yara", "Mitre", "VirusTotal"):
            root = Path(roots[root_name])
            records.extend(
                (root_name, (root / filename).as_posix())
                for filename in sorted(control_names[root_name])
            )
        return tuple(records)

    def standalone_package_resources(self) -> tuple[tuple[str, str], ...]:
        """Return every exact governed file admitted into a standalone package."""
        return tuple(sorted(
            (*self.immutable_package_resources(), *self.generated_control_resources()),
            key=lambda record: (record[0], record[1]),
        ))

    def to_record(self) -> dict[str, str]:
        return {
            "mitre_root": self.mitre_root,
            "mitre_seed_path": self.mitre_seed_path,
            "program_root": self.program_root,
            "scan_logs_root": self.scan_logs_root,
            "schema_version": self.schema_version,
            "semantic_digest": self.semantic_digest,
            "virustotal_root": self.virustotal_root,
            "yara_root": self.yara_root,
        }


def resource_root_snapshot_from_program_root(root: object) -> ResourceRootSnapshot:
    """Build the canonical root snapshot for one explicit program root."""
    resolved = _resolved_contract_path(root, "program_root")
    return ResourceRootSnapshot(
        program_root=resolved.as_posix(),
        yara_root=(resolved / "Yara").as_posix(),
        mitre_root=(resolved / "Mitre").as_posix(),
        mitre_seed_path=(resolved / "Mitre" / _MITRE_SEED_NAME).as_posix(),
        virustotal_root=(resolved / "VirusTotal").as_posix(),
        scan_logs_root=(resolved / "Scan Logs").as_posix(),
    )


def resource_root_snapshot() -> ResourceRootSnapshot:
    return resource_root_snapshot_from_program_root(program_root())


def _exact_positive_int(value: object, reason: str) -> int:
    if type(value) is not int or type(value) is bool or value <= 0:
        raise ValueError(reason)
    return value


def derive_scan_log_scan_id(*, session_generation: object, started_ns: object) -> str:
    if type(session_generation) is not str:
        raise TypeError("scan_log_session_generation_required")
    generation = str.__str__(session_generation).lower()
    if len(generation) != 64 or any(ch not in "0123456789abcdef" for ch in generation):
        raise ValueError("scan_log_session_generation_invalid")
    if type(started_ns) is not int or type(started_ns) is bool or started_ns < 0:
        raise ValueError("scan_log_started_ns_invalid")
    suffix = hashlib.sha256(
        (generation + ":" + int.__str__(started_ns)).encode("ascii")
    ).hexdigest()[:20]
    started_text = int.__str__(started_ns).rjust(20, "0")
    return "scan-" + started_text + "-" + suffix


@dataclass(frozen=True, slots=True)
class ScanLogOutputPlan:
    """Exact immutable staging/final paths for one publication generation."""

    scan_log_root: str
    scan_id: str
    staging_path: str
    run_path: str
    latest_path: str
    report_paths: tuple[tuple[str, str], ...]
    incomplete_retention: int = 8
    completed_retention: int = 32
    schema_version: str = SCAN_LOG_OUTPUT_PLAN_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not ScanLogOutputPlan:
            raise TypeError("scan_log_output_plan_owner_rejected")
        if type(self.schema_version) is not str or self.schema_version != SCAN_LOG_OUTPUT_PLAN_SCHEMA_VERSION:
            raise ValueError("scan_log_output_plan_schema_invalid")
        if type(self.scan_id) is not str or _SCAN_ID_RE.fullmatch(self.scan_id) is None:
            raise ValueError("scan_log_scan_id_invalid")
        root = _resolved_contract_path(self.scan_log_root, "scan_log_root")
        if root.name != "Scan Logs":
            raise ValueError("scan_log_root_invalid")
        expected_staging = root / ".staging" / self.scan_id
        expected_run = root / "runs" / self.scan_id
        expected_latest = root / "latest.json"
        exact_paths = (
            ("scan_log_root", root, self.scan_log_root),
            ("staging_path", expected_staging, self.staging_path),
            ("run_path", expected_run, self.run_path),
            ("latest_path", expected_latest, self.latest_path),
        )
        for field_name, expected, raw in exact_paths:
            actual = _resolved_contract_path(raw, field_name)
            if actual != expected:
                raise ValueError("scan_log_output_plan_path_invalid:" + field_name)
            object.__setattr__(self, field_name, actual.as_posix())
        reports = self.report_paths
        if type(reports) is not tuple or any(
            type(item) is not tuple or len(item) != 2
            or type(item[0]) is not str or type(item[1]) is not str
            for item in reports
        ):
            raise TypeError("scan_log_report_paths_invalid")
        expected_reports = tuple(
            (name, (expected_run / name).as_posix())
            for name in _SCAN_LOG_REPORT_FILENAMES
        )
        if reports != expected_reports:
            raise ValueError("scan_log_report_paths_mismatch")
        object.__setattr__(self, "report_paths", expected_reports)
        object.__setattr__(
            self,
            "incomplete_retention",
            _exact_positive_int(self.incomplete_retention, "scan_log_incomplete_retention_invalid"),
        )
        object.__setattr__(
            self,
            "completed_retention",
            _exact_positive_int(self.completed_retention, "scan_log_completed_retention_invalid"),
        )

    @property
    def semantic_digest(self) -> str:
        payload = "\n".join((
            self.schema_version,
            self.scan_log_root,
            self.scan_id,
            self.staging_path,
            self.run_path,
            self.latest_path,
            int.__str__(self.incomplete_retention),
            int.__str__(self.completed_retention),
            *(name + "=" + path for name, path in self.report_paths),
        ))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def report_path(self, filename: object) -> Path:
        if type(filename) is not str:
            raise TypeError("scan_log_report_filename_required")
        name = str.__str__(filename)
        for owned_name, owned_path in self.report_paths:
            if owned_name == name:
                return Path(owned_path)
        raise KeyError("scan_log_report_filename_unknown")

    def staging_report_path(self, filename: object) -> Path:
        final = self.report_path(filename)
        return Path(self.staging_path) / final.name

    def to_record(self) -> dict[str, object]:
        return {
            "completed_retention": self.completed_retention,
            "incomplete_retention": self.incomplete_retention,
            "latest_path": self.latest_path,
            "report_paths": {name: path for name, path in self.report_paths},
            "run_path": self.run_path,
            "scan_id": self.scan_id,
            "scan_log_root": self.scan_log_root,
            "schema_version": self.schema_version,
            "semantic_digest": self.semantic_digest,
            "staging_path": self.staging_path,
        }


def build_scan_log_output_plan(
    *,
    scan_id: object,
    root: object | None = None,
    incomplete_retention: object = 8,
    completed_retention: object = 32,
) -> ScanLogOutputPlan:
    if type(scan_id) is not str:
        raise TypeError("scan_log_scan_id_required")
    scan_id_text = str.__str__(scan_id).lower()
    if _SCAN_ID_RE.fullmatch(scan_id_text) is None:
        raise ValueError("scan_log_scan_id_invalid")
    resolved_root = scan_logs_dir() if root is None else _resolved_contract_path(root, "scan_log_root")
    staging = resolved_root / ".staging" / scan_id_text
    run = resolved_root / "runs" / scan_id_text
    return ScanLogOutputPlan(
        scan_log_root=resolved_root.as_posix(),
        scan_id=scan_id_text,
        staging_path=staging.as_posix(),
        run_path=run.as_posix(),
        latest_path=(resolved_root / "latest.json").as_posix(),
        report_paths=tuple(
            (name, (run / name).as_posix())
            for name in _SCAN_LOG_REPORT_FILENAMES
        ),
        incomplete_retention=_exact_positive_int(
            incomplete_retention,
            "scan_log_incomplete_retention_invalid",
        ),
        completed_retention=_exact_positive_int(
            completed_retention,
            "scan_log_completed_retention_invalid",
        ),
    )


def profiles_dir() -> Path:
    return program_root() / "Virus_Scan" / "profiles" if (program_root() / "Virus_Scan" / "profiles").is_dir() else resource_dir("profiles")


def state_file(name: str) -> Path:
    name_text = _resource_path_text(name, "state_file_name")
    if name_text is None:
        raise ValueError("state_file_name_missing")
    return program_root() / name_text


__all__ = (
    "RESOURCE_CLASSIFICATION_FINAL_PUBLICATION",
    "RESOURCE_CLASSIFICATION_PACKAGE",
    "RESOURCE_CLASSIFICATION_ROOT",
    "RESOURCE_CLASSIFICATION_RUNTIME_CACHE",
    "RESOURCE_CLASSIFICATION_RUNTIME_CONTROL",
    "RESOURCE_CLASSIFICATION_RUNTIME_STATE",
    "RESOURCE_CLASSIFICATION_SECRET_REFERENCE",
    "RESOURCE_CLASSIFICATION_STAGING_OUTPUT",
    "RESOURCE_CLASSIFICATION_UNKNOWN",
    "RESOURCE_ROOT_SNAPSHOT_SCHEMA_VERSION",
    "SCAN_LOG_OUTPUT_PLAN_SCHEMA_VERSION",
    "ResourceRootSnapshot",
    "ScanLogOutputPlan",
    "build_scan_log_output_plan",
    "derive_scan_log_scan_id",
    "mitre_dir",
    "profiles_dir",
    "program_root",
    "resource_dir",
    "resource_root_snapshot",
    "resource_root_snapshot_from_program_root",
    "scan_logs_dir",
    "state_file",
    "temp_dir",
    "virustotal_dir",
    "work_queue_dir",
    "yara_dir",
)
