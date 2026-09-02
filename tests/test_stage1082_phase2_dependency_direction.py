"""Phase 2 dependency-direction architecture guards.

These tests enforce the repository-level ownership rule from the remediation
command using AST inspection of production imports.  They intentionally inspect
actual Python source and do not import production modules, so they cannot hide
import side effects or mutate runtime state while validating dependency shape.
"""
from __future__ import annotations

import ast
from functools import lru_cache
from types import MappingProxyType
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VIRUS_SCAN = ROOT / "Virus_Scan"

PUBLIC_DOMAIN_PREFIXES = MappingProxyType({
    "detection": ("Virus_Scan.detection.api.", "Virus_Scan.detection.api"),
    "scanners": ("Virus_Scan.scanners.api.", "Virus_Scan.scanners.api"),
    "scheduler": ("Virus_Scan.scheduler.api.", "Virus_Scan.scheduler.api"),
    "publication": ("Virus_Scan.publication.api.", "Virus_Scan.publication.api"),
    "runtime": ("Virus_Scan.runtime.api.", "Virus_Scan.runtime.api"),
})

def _production_python_files() -> list[Path]:
    return [
        path
        for path in sorted(VIRUS_SCAN.rglob("*.py"))
        if "__pycache__" not in path.parts and "tests" not in path.parts
    ]


def _domain_for_file(path: Path) -> str:
    relative = path.relative_to(VIRUS_SCAN)
    return relative.parts[0] if len(relative.parts) > 1 else relative.name


def _module_for_path(path: Path) -> str:
    return ".".join(path.relative_to(ROOT).with_suffix("").parts)


def _resolve_import_module(current_module: str, node: ast.ImportFrom) -> str:
    if node.level == 0:
        return node.module or ""
    current_parts = current_module.split(".")
    base_parts = current_parts[:-node.level]
    if node.module:
        base_parts.append(node.module)
    return ".".join(base_parts)


@lru_cache(maxsize=1)
def _virus_scan_import_records() -> tuple[tuple[Path, int, str, str, tuple[str, ...]], ...]:
    records: list[tuple[Path, int, str, str, tuple[str, ...]]] = []
    for path in _production_python_files():
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text, filename=str(path))
        source_domain = _domain_for_file(path)
        source_module = _module_for_path(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported = alias.name
                    if imported.startswith("Virus_Scan"):
                        records.append((path, node.lineno, source_domain, imported, ()))
            elif isinstance(node, ast.ImportFrom):
                imported = _resolve_import_module(source_module, node)
                if imported.startswith("Virus_Scan"):
                    names = tuple(alias.name for alias in node.names)
                    records.append((path, node.lineno, source_domain, imported, names))
    return tuple(records)


def _iter_virus_scan_imports():
    yield from _virus_scan_import_records()


def _target_domain(imported: str) -> str | None:
    parts = imported.split(".")
    if len(parts) < 2 or parts[0] != "Virus_Scan":
        return None
    return parts[1]


def _is_public_import(target_domain: str, imported: str, names: tuple[str, ...]) -> bool:
    prefixes = PUBLIC_DOMAIN_PREFIXES.get(target_domain, ())
    if imported in prefixes or any(imported.startswith(prefix) for prefix in prefixes):
        return True
    return False


def test_scanners_do_not_import_detection_domain() -> None:
    offenders = []
    for path, lineno, source_domain, imported, names in _iter_virus_scan_imports():
        if source_domain == "scanners" and _target_domain(imported) == "detection":
            offenders.append(f"{path.relative_to(ROOT)}:{lineno} imports {imported} {names}")
    assert offenders == []


def test_detection_does_not_import_scanner_implementation_modules() -> None:
    offenders = []
    for path, lineno, source_domain, imported, names in _iter_virus_scan_imports():
        if source_domain == "detection" and _target_domain(imported) == "scanners":
            offenders.append(f"{path.relative_to(ROOT)}:{lineno} imports {imported} {names}")
    assert offenders == []


def test_scheduler_uses_only_public_scanner_and_detection_boundaries() -> None:
    offenders = []
    for path, lineno, source_domain, imported, names in _iter_virus_scan_imports():
        target_domain = _target_domain(imported)
        if source_domain == "scheduler" and target_domain in {"scanners", "detection"}:
            if not _is_public_import(target_domain, imported, names):
                offenders.append(f"{path.relative_to(ROOT)}:{lineno} imports {imported} {names}")
    assert offenders == []


def test_publication_runtime_and_reports_do_not_import_private_domain_internals() -> None:
    inspected_domains = {"publication", "runtime", "reporting", "reports", "init_runtime", "startup"}
    target_domains = {"scanners", "detection", "scheduler"}
    offenders = []
    for path, lineno, source_domain, imported, names in _iter_virus_scan_imports():
        target_domain = _target_domain(imported)
        if source_domain in inspected_domains and target_domain in target_domains:
            if not _is_public_import(target_domain, imported, names):
                offenders.append(f"{path.relative_to(ROOT)}:{lineno} imports {imported} {names}")
    assert offenders == []


def test_orchestration_and_bootstrap_use_public_runtime_boundary() -> None:
    inspected_domains = {"orchestration", "init_runtime", "startup"}
    offenders = []
    for path, lineno, source_domain, imported, names in _iter_virus_scan_imports():
        if source_domain in inspected_domains and _target_domain(imported) == "runtime":
            if not _is_public_import("runtime", imported, names):
                offenders.append(f"{path.relative_to(ROOT)}:{lineno} imports {imported} {names}")
    assert offenders == []


def test_publication_uses_public_runtime_boundary() -> None:
    offenders = []
    for path, lineno, source_domain, imported, names in _iter_virus_scan_imports():
        if source_domain == "publication" and _target_domain(imported) == "runtime":
            if not _is_public_import("runtime", imported, names):
                offenders.append(f"{path.relative_to(ROOT)}:{lineno} imports {imported} {names}")
    assert offenders == []


def test_reporting_uses_public_runtime_boundary() -> None:
    offenders = []
    for path, lineno, source_domain, imported, names in _iter_virus_scan_imports():
        if source_domain == "reporting" and _target_domain(imported) == "runtime":
            if not _is_public_import("runtime", imported, names):
                offenders.append(f"{path.relative_to(ROOT)}:{lineno} imports {imported} {names}")
    assert offenders == []

def test_detection_uses_public_runtime_boundary() -> None:
    offenders = []
    for path, lineno, source_domain, imported, names in _iter_virus_scan_imports():
        if source_domain == "detection" and _target_domain(imported) == "runtime":
            if not _is_public_import("runtime", imported, names):
                offenders.append(f"{path.relative_to(ROOT)}:{lineno} imports {imported} {names}")
    assert offenders == []

def test_scheduler_uses_public_runtime_boundary() -> None:
    offenders = []
    for path, lineno, source_domain, imported, names in _iter_virus_scan_imports():
        if source_domain == "scheduler" and _target_domain(imported) == "runtime":
            if not _is_public_import("runtime", imported, names):
                offenders.append(f"{path.relative_to(ROOT)}:{lineno} imports {imported} {names}")
    assert offenders == []

def test_scanners_use_public_runtime_boundary() -> None:
    offenders = []
    for path, lineno, source_domain, imported, names in _iter_virus_scan_imports():
        if source_domain == "scanners" and _target_domain(imported) == "runtime":
            if not _is_public_import("runtime", imported, names):
                offenders.append(f"{path.relative_to(ROOT)}:{lineno} imports {imported} {names}")
    assert offenders == []

def test_repository_level_detection_entrypoints_use_public_detection_boundary() -> None:
    inspected_domains = {"tags.py", "chains.py"}
    offenders = []
    for path, lineno, source_domain, imported, names in _iter_virus_scan_imports():
        if source_domain in inspected_domains and _target_domain(imported) == "detection":
            if not _is_public_import("detection", imported, names):
                offenders.append(f"{path.relative_to(ROOT)}:{lineno} imports {imported} {names}")
    assert offenders == []

def test_repository_level_persistence_uses_public_runtime_boundary() -> None:
    offenders = []
    for path, lineno, source_domain, imported, names in _iter_virus_scan_imports():
        if source_domain == "persistence.py" and _target_domain(imported) == "runtime":
            if not _is_public_import("runtime", imported, names):
                offenders.append(f"{path.relative_to(ROOT)}:{lineno} imports {imported} {names}")
    assert offenders == []

def test_models_use_public_detection_scanner_and_scheduler_boundaries() -> None:
    offenders = []
    for path, lineno, source_domain, imported, names in _iter_virus_scan_imports():
        target_domain = _target_domain(imported)
        if source_domain == "models" and target_domain in {"detection", "scanners", "scheduler"}:
            if not _is_public_import(target_domain, imported, names):
                offenders.append(f"{path.relative_to(ROOT)}:{lineno} imports {imported} {names}")
    assert offenders == []

def test_routing_uses_public_detection_scanner_and_scheduler_boundaries() -> None:
    offenders = []
    for path, lineno, source_domain, imported, names in _iter_virus_scan_imports():
        target_domain = _target_domain(imported)
        if source_domain == "routing" and target_domain in {"detection", "scanners", "scheduler"}:
            if not _is_public_import(target_domain, imported, names):
                offenders.append(f"{path.relative_to(ROOT)}:{lineno} imports {imported} {names}")
    assert offenders == []



def test_routing_uses_public_runtime_boundary() -> None:
    offenders = []
    for path, lineno, source_domain, imported, names in _iter_virus_scan_imports():
        if source_domain == "routing" and _target_domain(imported) == "runtime":
            if not _is_public_import("runtime", imported, names):
                offenders.append(f"{path.relative_to(ROOT)}:{lineno} imports {imported} {names}")
    assert offenders == []

def test_cli_uses_public_runtime_boundary() -> None:
    offenders = []
    for path, lineno, source_domain, imported, names in _iter_virus_scan_imports():
        if source_domain == "cli" and _target_domain(imported) == "runtime":
            if not _is_public_import("runtime", imported, names):
                offenders.append(f"{path.relative_to(ROOT)}:{lineno} imports {imported} {names}")
    assert offenders == []

def test_contracts_do_not_import_runtime_implementation_modules() -> None:
    offenders = []
    for path, lineno, source_domain, imported, names in _iter_virus_scan_imports():
        if source_domain == "contracts" and _target_domain(imported) == "runtime":
            offenders.append(f"{path.relative_to(ROOT)}:{lineno} imports {imported} {names}")
    assert offenders == []

def test_yara_does_not_import_detection_or_model_implementation_modules() -> None:
    offenders = []
    for path, lineno, source_domain, imported, names in _iter_virus_scan_imports():
        if source_domain == "yara" and _target_domain(imported) in {"detection", "models"}:
            offenders.append(f"{path.relative_to(ROOT)}:{lineno} imports {imported} {names}")
    assert offenders == []

def test_stress_corpus_uses_scanner_filetype_policy_not_detection_scoring_internals() -> None:
    offenders = []
    for path, lineno, source_domain, imported, names in _iter_virus_scan_imports():
        if source_domain == "stress" and imported.startswith("Virus_Scan.detection.scoring"):
            offenders.append(f"{path.relative_to(ROOT)}:{lineno} imports {imported} {names}")
    assert offenders == []

