"""Phase 9 archive/RPA ownership boundary audit."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import ast
from pathlib import Path

from Virus_Scan.contracts.no_hook_materialization import no_hook_ast_field_status

_REQUIRED_ARCHIVE_MODULES = frozenset({
    "__init__.py",
    "bounds.py",
    "common.py",
    "ecosystem.py",
    "evidence.py",
    "malformed.py",
    "member_scan.py",
    "payloads.py",
    "rpa.py",
    "rpa_member_behavior.py",
    "scanner.py",
    "tar_scanner.py",
    "zip_scanner.py",
})
_MAX_ARCHIVE_MODULE_LINES = 200
_MAX_ARCHIVE_FUNCTION_LINES = 75


@dataclass(frozen=True, slots=True)
class ArchiveBoundaryFinding:
    path: str
    category: str
    detail: str

    def to_record(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ArchiveBoundaryAuditResult:
    files_scanned: int
    findings: tuple[ArchiveBoundaryFinding, ...]

    @property
    def ok(self) -> bool:
        return not self.findings

    def to_record(self) -> dict[str, object]:
        return {
            "files_scanned": self.files_scanned,
            "findings": [finding.to_record() for finding in self.findings],
            "ok": self.ok,
        }


def _relative_path_text(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _ast_function_name(node: ast.AST) -> str:
    if type(node) not in (ast.FunctionDef, ast.AsyncFunctionDef):
        return "unknown_function"
    value, reason = no_hook_ast_field_status(node, (type(node),), "name")
    if reason:
        return "unknown_function"
    if type(value) is str and value:
        return str.__str__(value)
    return "unknown_function"


def _ast_function_line_number(node: ast.AST, field_name: str) -> int | None:
    if type(node) not in (ast.FunctionDef, ast.AsyncFunctionDef):
        return None
    if field_name not in {"lineno", "end_lineno"}:
        return None
    value, reason = no_hook_ast_field_status(node, (type(node),), field_name)
    if reason:
        return None
    if type(value) is int and type(value) is not bool and value >= 0:
        return value
    return None


def _function_length(node: ast.AST) -> int:
    end = _ast_function_line_number(node, "end_lineno")
    start = _ast_function_line_number(node, "lineno")
    if start is None and end is None:
        return 0
    if start is None:
        start = end if end is not None else 0
    if end is None:
        end = start
    return max(0, end - start + 1)


def _line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8", errors="ignore").splitlines())


def _module_mutable_assignment(node: ast.AST) -> bool:
    if not isinstance(node, ast.Assign):
        return False
    if any(not isinstance(target, ast.Name) or not target.id.isupper() for target in node.targets):
        return False
    return isinstance(node.value, (ast.List, ast.Dict, ast.Set))


def _imports_runtime_detector_error_without_malformed_helper(tree: ast.Module) -> bool:
    has_detector_import = False
    has_helper_import = False
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "Virus_Scan.runtime.scan_dependencies":
            has_detector_import = any(alias.name == "record_detector_error" for alias in node.names)
        if isinstance(node, ast.ImportFrom) and node.module == "Virus_Scan.scanners.archives.malformed":
            has_helper_import = any(alias.name == "append_archive_failure_evidence" for alias in node.names)
    return has_detector_import and not has_helper_import


def run_archive_boundary_audit(repo_root: str | Path = ".") -> ArchiveBoundaryAuditResult:
    root = Path(repo_root)
    scanner_archive_file = root / "Virus_Scan" / "scanners" / "archives.py"
    archive_dir = root / "Virus_Scan" / "scanners" / "archives"
    findings: list[ArchiveBoundaryFinding] = []
    if scanner_archive_file.exists():
        findings.append(ArchiveBoundaryFinding(_relative_path_text(scanner_archive_file, root), "legacy_archive_module_present", "archives.py still exists"))
    existing = {path.name for path in archive_dir.glob("*.py")}
    findings.extend(
        ArchiveBoundaryFinding(_relative_path_text(archive_dir, root), "missing_archive_boundary_module", name)
        for name in sorted(_REQUIRED_ARCHIVE_MODULES - existing)
    )
    files = sorted(archive_dir.glob("*.py"))
    for path in files:
        rel = path.relative_to(root)
        text = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(text)
        lines = _line_count(path)
        if lines > _MAX_ARCHIVE_MODULE_LINES:
            findings.append(ArchiveBoundaryFinding(rel.as_posix(), "archive_module_too_large", str(lines)))
        if _imports_runtime_detector_error_without_malformed_helper(tree) and path.name not in {"malformed.py", "zip_scanner.py", "tar_scanner.py"}:
            findings.append(ArchiveBoundaryFinding(rel.as_posix(), "direct_archive_failure_evidence", "record_detector_error imported outside malformed boundary"))
        for node in tree.body:
            if isinstance(node, ast.Assign) and _module_mutable_assignment(node):
                findings.append(ArchiveBoundaryFinding(rel.as_posix(), "mutable_module_policy", ast.dump(node.targets[0])))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _function_length(node) > _MAX_ARCHIVE_FUNCTION_LINES:
                findings.append(ArchiveBoundaryFinding(rel.as_posix(), "archive_function_too_large", _ast_function_name(node) + ":" + str(_function_length(node))))
    return ArchiveBoundaryAuditResult(files_scanned=len(files), findings=tuple(findings))


__all__ = ("ArchiveBoundaryAuditResult", "ArchiveBoundaryFinding", "run_archive_boundary_audit")
