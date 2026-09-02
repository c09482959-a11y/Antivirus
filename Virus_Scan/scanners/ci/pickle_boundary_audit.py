"""Phase 8 pickle ownership boundary audit."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import ast
from pathlib import Path

from Virus_Scan.contracts.no_hook_materialization import no_hook_ast_field_status


@dataclass(frozen=True, slots=True)
class PickleBoundaryFinding:
    path: str
    category: str
    detail: str

    def to_record(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PickleBoundaryAuditResult:
    files_scanned: int
    findings: tuple[PickleBoundaryFinding, ...]

    @property
    def ok(self) -> bool:
        return not self.findings

    def to_record(self) -> dict[str, object]:
        return {
            "files_scanned": self.files_scanned,
            "findings": [finding.to_record() for finding in self.findings],
            "ok": self.ok,
        }


_MAX_PICKLE_MODULE_LINES = 200
_MAX_PICKLE_FUNCTION_LINES = 75


def _line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8", errors="ignore").splitlines())


def _ast_int_field(node: ast.AST, name: str, replacement: int) -> int:
    value, reason = no_hook_ast_field_status(node, (type(node),), name)
    if reason:
        return replacement
    return value if type(value) is int and type(value) is not bool else replacement


def _ast_text(value: object) -> str:
    return value if type(value) is str else ""


def _rel_path_text(path: Path) -> str:
    return Path.as_posix(path)


def _function_length(node: ast.AST) -> int:
    end = _ast_int_field(node, "end_lineno", _ast_int_field(node, "lineno", 0))
    start = _ast_int_field(node, "lineno", end)
    return max(0, end - start + 1)


def _has_legacy_pickle_scan_import(node: ast.AST) -> bool:
    legacy_module = "Virus_Scan.scanners." + "pickle_scan"
    if isinstance(node, ast.ImportFrom):
        return _ast_text(node.module) == legacy_module
    if isinstance(node, ast.Import):
        return any(_ast_text(alias.name) == legacy_module for alias in node.names)
    return False


def _module_mutable_assignment(node: ast.AST) -> bool:
    if not isinstance(node, ast.Assign):
        return False
    if any(not isinstance(target, ast.Name) or not target.id.isupper() for target in node.targets):
        return False
    return isinstance(node.value, (ast.List, ast.Dict, ast.Set))


def run_pickle_boundary_audit(repo_root: str | Path = ".") -> PickleBoundaryAuditResult:
    root = Path(repo_root)
    scanners = root / "Virus_Scan" / "scanners"
    pickle_dir = scanners / "pickle"
    findings: list[PickleBoundaryFinding] = []
    files: list[Path] = []
    pickle_scan = scanners / "pickle_scan.py"
    if pickle_scan.exists():
        files.append(pickle_scan)
        tree = ast.parse(pickle_scan.read_text(encoding="utf-8", errors="ignore"))
        public_defs = [node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        if public_defs:
            findings.append(PickleBoundaryFinding(Path.as_posix(pickle_scan), "pickle_scan_owns_implementation", ",".join(public_defs)))
    for path in sorted(pickle_dir.glob("*.py")):
        files.append(path)
        rel = path.relative_to(root)
        text = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(text)
        if _line_count(path) > _MAX_PICKLE_MODULE_LINES:
            findings.append(PickleBoundaryFinding(_rel_path_text(rel), "pickle_module_too_large", str(_line_count(path))))
        for node in tree.body:
            if _has_legacy_pickle_scan_import(node):
                findings.append(PickleBoundaryFinding(_rel_path_text(rel), "imports_legacy_pickle_scan", ast.dump(node)))
            if isinstance(node, ast.Assign) and _module_mutable_assignment(node):
                findings.append(PickleBoundaryFinding(_rel_path_text(rel), "mutable_module_policy", ast.dump(node.targets[0])))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _function_length(node) > _MAX_PICKLE_FUNCTION_LINES:
                findings.append(PickleBoundaryFinding(_rel_path_text(rel), "pickle_function_too_large", _ast_text(node.name) + ":" + str(_function_length(node))))
    return PickleBoundaryAuditResult(files_scanned=len(files), findings=tuple(findings))


__all__ = ("PickleBoundaryAuditResult", "PickleBoundaryFinding", "run_pickle_boundary_audit")
