"""Phase 5 production caller scanner-import audit.

The gate parses production Python files and verifies non-scanner code reaches the
scanner subsystem only through the bounded ``Virus_Scan.scanners.api`` public
contract namespace.  Tests and scanner-owned implementation modules are outside
this production caller gate.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import ast
from pathlib import Path

from Virus_Scan.contracts.no_hook_materialization import no_hook_ast_field_status

_ALLOWED_PRODUCTION_PREFIX = "Virus_Scan.scanners.api"
_DISALLOWED_ROOT = "Virus_Scan.scanners"
_EXCLUDED_PATH_PARTS = frozenset({"tests", "scanners"})


@dataclass(frozen=True, slots=True)
class ScannerProductionImportFinding:
    path: str
    line: int
    module: str
    names: tuple[str, ...]

    def to_record(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ScannerProductionImportAuditResult:
    findings: tuple[ScannerProductionImportFinding, ...]
    scanned_files: int

    @property
    def ok(self) -> bool:
        return not self.findings

    def to_record(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "scanned_files": self.scanned_files,
            "findings": [finding.to_record() for finding in self.findings],
        }


def _ast_line(node: ast.AST) -> int:
    value, reason = no_hook_ast_field_status(node, (type(node),), "lineno")
    if reason:
        return 0
    return value if type(value) is int and type(value) is not bool else 0


def _ast_text(value: object) -> str:
    return value if type(value) is str else ""


def _rel_path_text(path: Path) -> str:
    return Path.as_posix(path)


def _is_production_python(path: Path, root: Path) -> bool:
    if not path.is_relative_to(root):
        return False
    rel = path.relative_to(root)
    parts = set(rel.parts)
    if path.suffix != ".py":
        return False
    if not rel.parts or rel.parts[0] != "Virus_Scan":
        return False
    return not (_EXCLUDED_PATH_PARTS & parts)


def _is_disallowed_scanner_module(module: str) -> bool:
    if module == _DISALLOWED_ROOT:
        return True
    if not module.startswith(_DISALLOWED_ROOT + "."):
        return False
    return not (module == _ALLOWED_PRODUCTION_PREFIX or module.startswith(_ALLOWED_PRODUCTION_PREFIX + "."))


def audit_production_scanner_imports(root: str | Path = ".") -> ScannerProductionImportAuditResult:
    base = Path(root)
    findings: list[ScannerProductionImportFinding] = []
    scanned = 0
    for path in sorted((base / "Virus_Scan").rglob("*.py")):
        if not _is_production_python(path, base):
            continue
        scanned += 1
        source = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source, filename=str(path))
        rel_path = _rel_path_text(path.relative_to(base))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and _is_disallowed_scanner_module(node.module):
                findings.extend(
                    (
                        ScannerProductionImportFinding(
                            rel_path,
                            _ast_line(node),
                            _ast_text(node.module),
                            tuple(_ast_text(alias.name) for alias in node.names if _ast_text(alias.name)),
                        ),
                    )
                )
            elif isinstance(node, ast.Import):
                findings.extend(
                    ScannerProductionImportFinding(
                        rel_path,
                        _ast_line(node),
                        _ast_text(alias.name),
                        (_ast_text(alias.asname) or _ast_text(alias.name),),
                    )
                    for alias in node.names
                    if _is_disallowed_scanner_module(alias.name)
                )
    return ScannerProductionImportAuditResult(tuple(findings), scanned)


__all__ = (
    "ScannerProductionImportAuditResult",
    "ScannerProductionImportFinding",
    "audit_production_scanner_imports",
)
