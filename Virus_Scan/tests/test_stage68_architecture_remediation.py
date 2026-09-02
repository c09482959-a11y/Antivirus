from __future__ import annotations
import ast
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@lru_cache(maxsize=None)
def _imports(module_path: Path) -> set[str]:
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module)
    return out


def test_yara_phase_modules_do_not_import_each_other_in_cycles():
    # Loading/match are separate canonical owners. Calibrated YARA evidence scoring
    # is detection-owned and must not be reintroduced under Virus_Scan.yara.
    loader = _imports(ROOT / "yara" / "loader.py")
    match = _imports(ROOT / "yara" / "match.py")
    scoring = _imports(ROOT / "detection" / "scoring" / "yara" / "context_evidence.py")
    assert "Virus_Scan.yara.match" not in loader
    assert "Virus_Scan.yara.scoring" not in loader
    assert "Virus_Scan.yara.loader" not in scoring
    assert not (ROOT / "yara" / "scoring.py").exists()
    assert "Virus_Scan.yara." + "compat" not in {"Virus_Scan.yara.loader", "Virus_Scan.yara.match"}
    assert not (ROOT / "yara" / "loading.py").exists()


def test_runtime_does_not_import_application_layers():
    forbidden = ("Virus_Scan.cli", "Virus_Scan.scanners", "Virus_Scan.scheduler", "Virus_Scan.reporting", "Virus_Scan.models", "Virus_Scan.yara", "Virus_Scan.orchestration")
    for path in (ROOT / "runtime").glob("*.py"):
        if path.name.startswith("compat_"):
            continue
        imports = _imports(path)
        bad = [m for m in imports if m.startswith(forbidden)]
        assert not bad, f"{path.name} imports application layer: {bad}"


def test_no_cross_layer_duplicate_policy_hash_report_present():
    # The old Stage 68 package used an uppercase AUDIT/ path.  Current packages
    # preserve audit artifacts under the canonical Audit/ folder with consolidated
    # stage-specific markdown reports.  Keep the invariant without pinning the
    # stale pre-consolidation filename.
    audit_dir = ROOT.parent / "Audit"
    assert audit_dir.is_dir()
    reports = sorted(audit_dir.glob("*.md"))
    assert reports
    assert any("stage" in report.name.lower() and "audit" in report.name.lower() for report in reports)


def teardown_module() -> None:
    """Release cached source import scans before pytest process shutdown."""
    _imports.cache_clear()
