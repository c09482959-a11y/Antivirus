from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


_STAGE416_STARTUP_IMPORT_MODULES = (
    "Virus_Scan.main",
    "Virus_Scan.cli.args",
    "Virus_Scan.orchestration",
    "Virus_Scan.reporting.output",
    "Virus_Scan.scheduler",
    "Virus_Scan.detection",
    "Virus_Scan.engine_routing",
    "Virus_Scan.yara",
    "Virus_Scan.scanners",
    "Virus_Scan.persistence",
    "Virus_Scan.scanners.binary",
)


def _subprocess_env(repo_root: Path, overrides: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(repo_root)
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    for key, value in (overrides or {}).items():
        env[str(key)] = str(value)
    return env


def _run_import(module: str, cwd: Path, repo_root: Path):
    return subprocess.run(
        [sys.executable, "-S", "-c", f"import {module}; print('ok')"],
        cwd=str(cwd),
        text=True,
        capture_output=True,
        timeout=30,
        env=_subprocess_env(repo_root),
    )


@pytest.mark.parametrize("module", _STAGE416_STARTUP_IMPORT_MODULES)
def test_clean_startup_imports_include_persistence_boundary(tmp_path, module):
    proc = _run_import(module, tmp_path, Path(__file__).resolve().parents[2])
    assert proc.returncode == 0, proc.stderr


def test_runtime_resource_paths_do_not_depend_on_launch_cwd(tmp_path):
    repo_root = Path(__file__).resolve().parents[2]
    script = (
        "from Virus_Scan.runtime.resource_paths import program_root, scan_logs_dir, yara_dir, temp_dir, work_queue_dir;"
        "print(program_root());print(scan_logs_dir());print(yara_dir());print(temp_dir());print(work_queue_dir())"
    )
    env = _subprocess_env(repo_root, {"UMIGE_BASE_DIR": str(repo_root)})
    first = subprocess.run([sys.executable, "-S", "-c", script], cwd=str(repo_root), text=True, capture_output=True, timeout=30, env=env)
    second = subprocess.run([sys.executable, "-S", "-c", script], cwd=str(tmp_path), text=True, capture_output=True, timeout=30, env=env)
    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert first.stdout == second.stdout
    assert str(tmp_path) not in second.stdout


def test_yara_and_scan_log_paths_are_owned_by_program_root(tmp_path):
    repo_root = Path(__file__).resolve().parents[2]
    script = (
        "from Virus_Scan.runtime.resource_paths import scan_logs_dir, yara_dir;"
        "print(scan_logs_dir());print(yara_dir())"
    )
    proc = subprocess.run(
        [sys.executable, "-S", "-c", script],
        cwd=str(tmp_path),
        text=True,
        capture_output=True,
        timeout=30,
        env=_subprocess_env(repo_root, {"UMIGE_BASE_DIR": str(repo_root)}),
    )
    assert proc.returncode == 0, proc.stderr
    lines = [Path(line).resolve() for line in proc.stdout.splitlines() if line.strip()]
    assert lines == [repo_root / "Scan Logs", repo_root / "Yara"]
