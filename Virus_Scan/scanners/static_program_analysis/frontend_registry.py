"""Single canonical registry of production static-program-analysis frontends."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from types import MappingProxyType
from typing import Callable, Mapping

from Virus_Scan.contracts.static_program_analysis import (
    STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST,
    STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION,
)
from Virus_Scan.scanners.static_program_analysis.batch_cmd_frontend import (
    BATCH_CMD_FRONTEND_DIGEST,
    BATCH_CMD_FRONTEND_SCHEMA_VERSION,
    BATCH_CMD_MAX_SOURCE_BYTES,
    BatchCmdAnalysisResult,
    analyze_batch_cmd_snapshot,
)
from Virus_Scan.scanners.static_program_analysis.dotnet_il_frontend import (
    DOTNET_IL_FRONTEND_DIGEST,
    DOTNET_IL_FRONTEND_SCHEMA_VERSION,
    DOTNET_IL_MAX_SOURCE_BYTES,
    DotNetILAnalysisResult,
    analyze_dotnet_il_snapshot,
)
from Virus_Scan.scanners.static_program_analysis.javascript_typescript_frontend import (
    JAVASCRIPT_TYPESCRIPT_FRONTEND_DIGEST,
    JAVASCRIPT_TYPESCRIPT_FRONTEND_SCHEMA_VERSION,
    JAVASCRIPT_TYPESCRIPT_MAX_SOURCE_BYTES,
    JavaScriptTypeScriptAnalysisResult,
    analyze_javascript_typescript_snapshot,
)
from Virus_Scan.scanners.static_program_analysis.native_elf_x86_64_frontend import (
    NATIVE_ELF_X86_64_FRONTEND_DIGEST,
    NATIVE_ELF_X86_64_FRONTEND_SCHEMA_VERSION,
    NATIVE_ELF_X86_64_MAX_SOURCE_BYTES,
    NativeELFX86_64AnalysisResult,
    analyze_native_elf_x86_64_snapshot,
)
from Virus_Scan.scanners.static_program_analysis.powershell_frontend import (
    POWERSHELL_FRONTEND_DIGEST,
    POWERSHELL_FRONTEND_SCHEMA_VERSION,
    POWERSHELL_MAX_SOURCE_BYTES,
    PowerShellAnalysisResult,
    analyze_powershell_snapshot,
)
from Virus_Scan.scanners.static_program_analysis.shell_frontend import (
    SHELL_FRONTEND_DIGEST,
    SHELL_FRONTEND_SCHEMA_VERSION,
    SHELL_MAX_SOURCE_BYTES,
    ShellAnalysisResult,
    analyze_shell_snapshot,
)
from Virus_Scan.scanners.static_program_analysis.python_frontend import (
    PYTHON_RENPY_FRONTEND_DIGEST,
    PYTHON_RENPY_FRONTEND_SCHEMA_VERSION,
    PYTHON_RENPY_MAX_SOURCE_BYTES,
    PythonRenpyAnalysisResult,
    analyze_python_renpy_snapshot,
)

STATIC_PROGRAM_ANALYSIS_PARSER_REGISTRY_VERSION = "static_program_analysis_parser_registry_v13"

StaticFrontendResult = (
    BatchCmdAnalysisResult
    | DotNetILAnalysisResult
    | JavaScriptTypeScriptAnalysisResult
    | NativeELFX86_64AnalysisResult
    | PowerShellAnalysisResult
    | ShellAnalysisResult
    | PythonRenpyAnalysisResult
)
StaticFrontendAnalyzer = Callable[[object], StaticFrontendResult]


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8", "strict")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class StaticProgramAnalysisFrontend:
    """One immutable language frontend binding owned by this registry."""

    scanner_id: str
    language: str
    extensions: tuple[str, ...]
    magic_types: tuple[str, ...]
    maximum_source_bytes: int
    schema_version: str
    frontend_digest: str
    analyzer: StaticFrontendAnalyzer

    def __post_init__(self) -> None:
        if type(self) is not StaticProgramAnalysisFrontend:
            raise TypeError("static_frontend_owner_invalid")
        if type(self.scanner_id) is not str or not self.scanner_id:
            raise ValueError("static_frontend_scanner_id_invalid")
        if type(self.language) is not str or not self.language:
            raise ValueError("static_frontend_language_invalid")
        if type(self.extensions) is not tuple or type(self.magic_types) is not tuple:
            raise TypeError("static_frontend_selectors_invalid")
        if not self.extensions and not self.magic_types:
            raise ValueError("static_frontend_selectors_missing")
        if any(type(item) is not str or not item.startswith(".") for item in self.extensions):
            raise ValueError("static_frontend_extensions_invalid")
        if tuple(sorted(set(self.extensions))) != self.extensions:
            raise ValueError("static_frontend_extensions_invalid")
        if any(type(item) is not str or not item for item in self.magic_types):
            raise ValueError("static_frontend_magic_types_invalid")
        if tuple(sorted(set(self.magic_types))) != self.magic_types:
            raise ValueError("static_frontend_magic_types_invalid")
        if (
            type(self.maximum_source_bytes) is not int
            or type(self.maximum_source_bytes) is bool
            or self.maximum_source_bytes <= 0
        ):
            raise ValueError("static_frontend_maximum_source_bytes_invalid")
        if type(self.schema_version) is not str or not self.schema_version:
            raise ValueError("static_frontend_schema_version_invalid")
        if type(self.frontend_digest) is not str or len(self.frontend_digest) != 64:
            raise ValueError("static_frontend_digest_invalid")
        if not callable(self.analyzer):
            raise TypeError("static_frontend_analyzer_invalid")

    def to_record(self) -> dict[str, object]:
        return {
            "digest": self.frontend_digest,
            "extensions": list(self.extensions),
            "language": self.language,
            "magic_types": list(self.magic_types),
            "maximum_source_bytes": self.maximum_source_bytes,
            "scanner_id": self.scanner_id,
            "schema_version": self.schema_version,
        }


def _build_frontends() -> tuple[StaticProgramAnalysisFrontend, ...]:
    """Construct the immutable implementation registry without policy-like module tables."""
    return (
        StaticProgramAnalysisFrontend(
            scanner_id="javascript_typescript_static_analysis",
            language="javascript_typescript",
            extensions=(".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx"),
            magic_types=(),
            maximum_source_bytes=JAVASCRIPT_TYPESCRIPT_MAX_SOURCE_BYTES,
            schema_version=JAVASCRIPT_TYPESCRIPT_FRONTEND_SCHEMA_VERSION,
            frontend_digest=JAVASCRIPT_TYPESCRIPT_FRONTEND_DIGEST,
            analyzer=analyze_javascript_typescript_snapshot,
        ),
        StaticProgramAnalysisFrontend(
            scanner_id="powershell_static_analysis",
            language="powershell",
            extensions=(".ps1", ".psm1"),
            magic_types=(),
            maximum_source_bytes=POWERSHELL_MAX_SOURCE_BYTES,
            schema_version=POWERSHELL_FRONTEND_SCHEMA_VERSION,
            frontend_digest=POWERSHELL_FRONTEND_DIGEST,
            analyzer=analyze_powershell_snapshot,
        ),
        StaticProgramAnalysisFrontend(
            scanner_id="batch_cmd_static_analysis",
            language="batch_cmd",
            extensions=(".bat", ".cmd"),
            magic_types=(),
            maximum_source_bytes=BATCH_CMD_MAX_SOURCE_BYTES,
            schema_version=BATCH_CMD_FRONTEND_SCHEMA_VERSION,
            frontend_digest=BATCH_CMD_FRONTEND_DIGEST,
            analyzer=analyze_batch_cmd_snapshot,
        ),
        StaticProgramAnalysisFrontend(
            scanner_id="shell_static_analysis",
            language="shell",
            extensions=(".sh",),
            magic_types=(),
            maximum_source_bytes=SHELL_MAX_SOURCE_BYTES,
            schema_version=SHELL_FRONTEND_SCHEMA_VERSION,
            frontend_digest=SHELL_FRONTEND_DIGEST,
            analyzer=analyze_shell_snapshot,
        ),
        StaticProgramAnalysisFrontend(
            scanner_id="dotnet_il_static_analysis",
            language="dotnet_il",
            extensions=(".dll", ".exe"),
            magic_types=(),
            maximum_source_bytes=DOTNET_IL_MAX_SOURCE_BYTES,
            schema_version=DOTNET_IL_FRONTEND_SCHEMA_VERSION,
            frontend_digest=DOTNET_IL_FRONTEND_DIGEST,
            analyzer=analyze_dotnet_il_snapshot,
        ),
        StaticProgramAnalysisFrontend(
            scanner_id="native_elf_x86_64_static_analysis",
            language="native_x86_64",
            extensions=(),
            magic_types=("elf",),
            maximum_source_bytes=NATIVE_ELF_X86_64_MAX_SOURCE_BYTES,
            schema_version=NATIVE_ELF_X86_64_FRONTEND_SCHEMA_VERSION,
            frontend_digest=NATIVE_ELF_X86_64_FRONTEND_DIGEST,
            analyzer=analyze_native_elf_x86_64_snapshot,
        ),
        StaticProgramAnalysisFrontend(
            scanner_id="python_renpy_static_analysis",
            language="python_renpy",
            extensions=(".py", ".pyw", ".rpy"),
            magic_types=(),
            maximum_source_bytes=PYTHON_RENPY_MAX_SOURCE_BYTES,
            schema_version=PYTHON_RENPY_FRONTEND_SCHEMA_VERSION,
            frontend_digest=PYTHON_RENPY_FRONTEND_DIGEST,
            analyzer=analyze_python_renpy_snapshot,
        ),
    )


def _build_frontend_indexes(
    frontends: tuple[StaticProgramAnalysisFrontend, ...],
) -> tuple[
    Mapping[str, StaticProgramAnalysisFrontend],
    Mapping[str, StaticProgramAnalysisFrontend],
    Mapping[str, StaticProgramAnalysisFrontend],
]:
    by_scanner_id = {item.scanner_id: item for item in frontends}
    if len(by_scanner_id) != len(frontends):
        raise RuntimeError("static_frontend_scanner_id_duplicate")

    by_extension: dict[str, StaticProgramAnalysisFrontend] = {}
    by_magic_type: dict[str, StaticProgramAnalysisFrontend] = {}
    for frontend in frontends:
        for extension in frontend.extensions:
            if extension in by_extension:
                raise RuntimeError("static_frontend_extension_owner_duplicate")
            by_extension[extension] = frontend
        for magic_type in frontend.magic_types:
            if magic_type in by_magic_type:
                raise RuntimeError("static_frontend_magic_owner_duplicate")
            by_magic_type[magic_type] = frontend
    return (
        MappingProxyType(by_scanner_id),
        MappingProxyType(by_extension),
        MappingProxyType(by_magic_type),
    )


STATIC_PROGRAM_ANALYSIS_FRONTENDS = _build_frontends()
(
    STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_SCANNER_ID,
    STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_EXTENSION,
    STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_MAGIC_TYPE,
) = _build_frontend_indexes(STATIC_PROGRAM_ANALYSIS_FRONTENDS)

STATIC_PROGRAM_ANALYSIS_PARSER_REGISTRY_DIGEST = _canonical_digest({
    "frontends": [item.to_record() for item in STATIC_PROGRAM_ANALYSIS_FRONTENDS],
    "ir_schema": STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION,
    "ir_schema_digest": STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST,
    "registry_version": STATIC_PROGRAM_ANALYSIS_PARSER_REGISTRY_VERSION,
})


def static_program_analysis_parser_registry_digest() -> str:
    return STATIC_PROGRAM_ANALYSIS_PARSER_REGISTRY_DIGEST


__all__ = (
    "STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_EXTENSION",
    "STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_SCANNER_ID",
    "STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_MAGIC_TYPE",
    "STATIC_PROGRAM_ANALYSIS_FRONTENDS",
    "STATIC_PROGRAM_ANALYSIS_PARSER_REGISTRY_DIGEST",
    "STATIC_PROGRAM_ANALYSIS_PARSER_REGISTRY_VERSION",
    "StaticProgramAnalysisFrontend",
    "static_program_analysis_parser_registry_digest",
)
