"""Phase 5 scanner public-export smoke gate.

This CI helper statically imports scanner modules, inventories module-owned public
functions and ``__all__`` exports, and calls each public callable with bounded
synthetic scanner inputs.  It is scanner-owned and intentionally avoids dynamic
imports/importlib so broken exports cannot be hidden behind runtime discovery.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from types import ModuleType
import zipfile
from typing import Callable

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_owner_field_status, no_hook_module_dict_status
from Virus_Scan.contracts.runtime_function_identity import RUNTIME_NATIVE_FUNCTION_TYPE, is_runtime_native_function

from Virus_Scan.scanners import archives, binary, dotnet, dotnet_identity, entropy, il_pipeline, ilspy, image, payload_decode, pickle_scan, pipeline, raw_chunk_collectors, raw_chunk_core, raw_chunk_engine_collectors, raw_chunk_headers, raw_queue_scan_result, renpy, rpgm, strings, text, unity
from Virus_Scan.scanners.ci.public_export_smoke_cases import build_public_export_smoke_cases

_ARCHIVES_MODULE = "Virus_Scan.scanners.archives"
_BINARY_MODULE = "Virus_Scan.scanners.binary"
_DOTNET_MODULE = "Virus_Scan.scanners.dotnet"
_DOTNET_IDENTITY_MODULE = "Virus_Scan.scanners.dotnet_identity"
_ENTROPY_MODULE = "Virus_Scan.scanners.entropy"
_IL_PIPELINE_MODULE = "Virus_Scan.scanners.il_pipeline"
_ILSPY_MODULE = "Virus_Scan.scanners.ilspy"
_IMAGE_MODULE = "Virus_Scan.scanners.image"
_PAYLOAD_DECODE_MODULE = "Virus_Scan.scanners.payload_decode"
_PICKLE_SCAN_MODULE = "Virus_Scan.scanners." + "pickle_scan"
_PIPELINE_MODULE = "Virus_Scan.scanners.pipeline"
_RAW_CHUNK_COLLECTORS_MODULE = "Virus_Scan.scanners.raw_chunk_collectors"
_RAW_CHUNK_CORE_MODULE = "Virus_Scan.scanners.raw_chunk_core"
_RAW_CHUNK_ENGINE_COLLECTORS_MODULE = "Virus_Scan.scanners.raw_chunk_engine_collectors"
_RAW_CHUNK_HEADERS_MODULE = "Virus_Scan.scanners.raw_chunk_headers"
_RAW_QUEUE_SCAN_RESULT_MODULE = "Virus_Scan.scanners.raw_queue_scan_result"
_RENPY_MODULE = "Virus_Scan.scanners.renpy"
_RPGM_MODULE = "Virus_Scan.scanners.rpgm"
_STRINGS_MODULE = "Virus_Scan.scanners.strings"
_TEXT_MODULE = "Virus_Scan.scanners.text"
_UNITY_MODULE = "Virus_Scan.scanners.unity"


_SCANNER_PUBLIC_MODULES = (
    (_ARCHIVES_MODULE, archives),
    (_BINARY_MODULE, binary),
    (_DOTNET_MODULE, dotnet),
    (_DOTNET_IDENTITY_MODULE, dotnet_identity),
    (_ENTROPY_MODULE, entropy),
    (_IL_PIPELINE_MODULE, il_pipeline),
    (_ILSPY_MODULE, ilspy),
    (_IMAGE_MODULE, image),
    (_PAYLOAD_DECODE_MODULE, payload_decode),
    (_PICKLE_SCAN_MODULE, pickle_scan),
    (_PIPELINE_MODULE, pipeline),
    (_RAW_CHUNK_COLLECTORS_MODULE, raw_chunk_collectors),
    (_RAW_CHUNK_CORE_MODULE, raw_chunk_core),
    (_RAW_CHUNK_ENGINE_COLLECTORS_MODULE, raw_chunk_engine_collectors),
    (_RAW_CHUNK_HEADERS_MODULE, raw_chunk_headers),
    (_RAW_QUEUE_SCAN_RESULT_MODULE, raw_queue_scan_result),
    (_RENPY_MODULE, renpy),
    (_RPGM_MODULE, rpgm),
    (_STRINGS_MODULE, strings),
    (_TEXT_MODULE, text),
    (_UNITY_MODULE, unity),
)
_SCANNER_PUBLIC_MODULE_NAMES = tuple(module_name for module_name, _module in _SCANNER_PUBLIC_MODULES)


def _module_dict(module: ModuleType) -> dict[str, object]:
    mapping, reason = no_hook_module_dict_status(module)
    if reason:
        return {}
    return mapping if mapping is not None else {}


def _module_all_names(module: ModuleType) -> tuple[str, ...]:
    raw = dict.get(_module_dict(module), "__all__", ())
    if type(raw) is tuple or type(raw) is list:
        return tuple(name for name in raw if type(name) is str)
    return ()


def _module_public_value(module: ModuleType, name: str) -> object:
    return dict.get(_module_dict(module), name) if type(name) is str else None


def _function_module_name(value: object) -> str:
    if not is_runtime_native_function(value):
        return ""
    module_name, reason = no_hook_exact_owner_field_status(value, RUNTIME_NATIVE_FUNCTION_TYPE, "__module__")
    if reason:
        return ""
    return module_name if type(module_name) is str else ""


def _unknown_module_name_message(module_name: str) -> str:
    return "unknown scanner public-export module name: " + module_name


def _scanner_public_module_for_name(module_name: str) -> ModuleType:
    for registered_name, module in _SCANNER_PUBLIC_MODULES:
        if module_name == registered_name:
            return module
    raise RuntimeError(_unknown_module_name_message(module_name))


@dataclass(frozen=True, slots=True)
class ScannerPublicExport:
    module: str
    name: str
    source: str
    callable_export: bool

    def key(self) -> tuple[str, str]:
        return (self.module, self.name)

    def to_record(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ScannerPublicExportSmokeRecord:
    module: str
    name: str
    status: str
    result_type: str
    error_type: str = ""
    message: str = ""

    def key(self) -> tuple[str, str]:
        return (self.module, self.name)

    def to_record(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ScannerPublicExportSmokeResult:
    exports: tuple[ScannerPublicExport, ...]
    records: tuple[ScannerPublicExportSmokeRecord, ...]
    missing_smoke_cases: tuple[tuple[str, str], ...]
    unexpected_errors: tuple[ScannerPublicExportSmokeRecord, ...]

    @property
    def ok(self) -> bool:
        return not self.missing_smoke_cases and not self.unexpected_errors

    def to_record(self) -> dict[str, object]:
        return {
            "exports": [record.to_record() for record in self.exports],
            "records": [record.to_record() for record in self.records],
            "missing_smoke_cases": list(self.missing_smoke_cases),
            "unexpected_errors": [record.to_record() for record in self.unexpected_errors],
            "ok": self.ok,
        }


def discover_scanner_public_exports() -> tuple[ScannerPublicExport, ...]:
    records: list[ScannerPublicExport] = []
    seen: set[tuple[str, str]] = set()
    for module_name in _SCANNER_PUBLIC_MODULE_NAMES:
        module = _scanner_public_module_for_name(module_name)
        exported_names = _module_all_names(module)
        for name in exported_names:
            key = (module_name, name)
            if key not in seen:
                seen.add(key)
                records.append(ScannerPublicExport(module_name, name, "__all__", callable(_module_public_value(module, name))))
        for name, value in sorted(dict.items(_module_dict(module))):
            if name.startswith("_"):
                continue
            if is_runtime_native_function(value) and _function_module_name(value) == module_name:
                key = (module_name, name)
                if key not in seen:
                    seen.add(key)
                    records.append(ScannerPublicExport(module_name, name, "module_public_function", callable_export=True))
    return tuple(records)


def _write_samples(base_dir: Path) -> dict[str, Path]:
    base_dir.mkdir(parents=True, exist_ok=True)
    text_path = base_dir / "sample.rpy"
    text_path.write_text("label start:\n    python:\n        import os\n        os.system('echo smoke')\nCreateFileA URLDownloadToFile package.json www/js", encoding="utf-8")
    binary_path = base_dir / "sample.dll"
    binary_path.write_bytes(b"MZ" + (b"\x00" * 58) + (b"\x80\x00\x00\x00") + (b"\x00" * 128) + b"BSJB Assembly-CSharp UnityEngine mscoree.dll #Strings #US #Blob")
    image_path = base_dir / "bad.png"
    image_path.write_bytes(b"not a valid image")
    rpa_path = base_dir / "scripts.rpa"
    rpa_path.write_bytes(b"RPA-3.0 00000010 00000000\nrenpy pickle python exec(")
    zip_path = base_dir / "archive.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("script.rpy", "python exec('x')")
    return {"text": text_path, "binary": binary_path, "image": image_path, "rpa": rpa_path, "zip": zip_path}



def _smoke_cases(samples: dict[str, Path]) -> dict[tuple[str, str], Callable[[], object]]:
    return build_public_export_smoke_cases(samples)


def run_public_export_smoke(base_dir: str | Path) -> ScannerPublicExportSmokeResult:
    samples = _write_samples(Path(base_dir))
    exports = discover_scanner_public_exports()
    smoke_cases = _smoke_cases(samples)
    callable_exports = {record.key() for record in exports if record.callable_export}
    missing = tuple(sorted(callable_exports - set(smoke_cases)))
    smoke_targets = tuple(sorted(callable_exports & set(smoke_cases)))
    records: list[ScannerPublicExportSmokeRecord] = []
    unexpected: list[ScannerPublicExportSmokeRecord] = []
    for module_name, export_name in smoke_targets:
        try:
            result = smoke_cases[(module_name, export_name)]()
            record = ScannerPublicExportSmokeRecord(module_name, export_name, "ok", type(result).__name__)
        except (NameError, AttributeError) as exc:
            record = ScannerPublicExportSmokeRecord(module_name, export_name, "broken_export", "", type(exc).__name__, str(exc)[:500])
            unexpected.append(record)
        except (OSError, TypeError, ValueError, RuntimeError, UnicodeError) as exc:
            record = ScannerPublicExportSmokeRecord(module_name, export_name, "typed_exception", "", type(exc).__name__, str(exc)[:500])
        records.append(record)
    return ScannerPublicExportSmokeResult(exports, tuple(records), missing, tuple(unexpected))


__all__ = (
    "ScannerPublicExport",
    "ScannerPublicExportSmokeRecord",
    "ScannerPublicExportSmokeResult",
    "discover_scanner_public_exports",
    "run_public_export_smoke",
)
