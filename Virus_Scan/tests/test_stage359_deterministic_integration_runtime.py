from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from Virus_Scan.tests.support.process_scheduler_capacity import process_scheduler_test_environment
from Virus_Scan.contracts.path_identity import should_include_scan_path
from Virus_Scan.runtime.determinism import (
    deterministic_json_digest,
    deterministic_path_inventory,
    make_governance_snapshot,
)
from Virus_Scan.runtime.cleanup_invariants import validate_runtime_cleanup
from Virus_Scan.scheduler.execution.target_collection import collect_target_files as collect_scheduler_target_files


ROOT = Path(__file__).resolve().parents[1]
_CLI_TIMEOUT_SECONDS = 180


def _write_corpus(root: Path) -> Path:
    corpus = root / "corpus"
    (corpus / "game" / "renpy").mkdir(parents=True)
    (corpus / "game" / "unity" / "Data" / "Managed").mkdir(parents=True)
    (corpus / "media").mkdir(parents=True)
    (corpus / "game" / "renpy" / "script.rpy").write_text("label start:\n    return\n", encoding="utf-8")
    (corpus / "game" / "unity" / "Data" / "Managed" / "Assembly-CSharp.dll").write_bytes(b"MZ" + b"\x00" * 32)
    (corpus / "media" / "clean.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 32)
    (corpus / "payload.bin").write_text("powershell -enc AAAA", encoding="utf-8")
    return corpus


def _isolated_cli_environment(runtime_root: Path) -> dict[str, str]:
    """Return a CLI subprocess environment isolated from prior pytest state."""
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("UMIGE_") and key != "PYTEST_CURRENT_TEST"
    }
    existing_pythonpath = env.get("PYTHONPATH")
    root_text = str(ROOT.parent)
    if existing_pythonpath:
        env["PYTHONPATH"] = os.pathsep.join((root_text, existing_pythonpath))
    else:
        env["PYTHONPATH"] = root_text
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["UMIGE_BASE_DIR"] = str(runtime_root.resolve())
    return process_scheduler_test_environment(env)


def _process_group_id(process: subprocess.Popen[object]) -> int | None:
    if os.name != "posix":
        return None
    try:
        return os.getpgid(process.pid)
    except (ProcessLookupError, PermissionError, OSError):
        return None


def _terminate_cli_process_group(process_group_id: int | None, *, force: bool = False) -> None:
    if os.name != "posix" or process_group_id is None:
        return
    signum = signal.SIGKILL if force else signal.SIGTERM
    try:
        os.killpg(process_group_id, signum)
    except (ProcessLookupError, PermissionError, OSError):
        return


def _run_cli(scan_root: Path, output_root: Path, *, scheduler: str) -> dict[str, object]:
    output_root.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        "-m",
        "Virus_Scan.runtime_main",
        "--dir",
        str(scan_root),
        "--no-yara",
        "--scheduler",
        scheduler,
        "--workers",
        "2",
        "--max-files",
        "25",
        "--scan-log-root",
        str(output_root / "Scan Logs"),
        "--no-scan-cache",
        "--deep-scan-mode",
        "auto",
    ]
    stdout_path = output_root / "scan_stdout.txt"
    stderr_path = output_root / "scan_stderr.txt"
    with stdout_path.open("w", encoding="utf-8") as stdout_file, stderr_path.open("w", encoding="utf-8") as stderr_file:
        process = subprocess.Popen(
            cmd,
            cwd=ROOT.parent,
            env=_isolated_cli_environment(output_root / "runtime_root"),
            text=True,
            stdout=stdout_file,
            stderr=stderr_file,
            start_new_session=(os.name == "posix"),
        )
        process_group_id = _process_group_id(process)
        try:
            returncode = process.wait(timeout=_CLI_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            _terminate_cli_process_group(process_group_id)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _terminate_cli_process_group(process_group_id, force=True)
                process.kill()
                process.wait(timeout=5)
            raise
        finally:
            _terminate_cli_process_group(process_group_id)
    diagnostic_output = stdout_path.read_text(encoding="utf-8") + stderr_path.read_text(encoding="utf-8")
    assert "Traceback (most recent call last)" not in diagnostic_output
    assert returncode in {0, 1, 2, 3}, diagnostic_output
    scan_logs = output_root / "Scan Logs"
    assert not tuple(path for path in (scan_logs / ".staging").glob("*") if path.is_dir()), diagnostic_output
    latest = json.loads((scan_logs / "latest.json").read_text(encoding="utf-8"))
    assert latest["completion_state"] == "complete", diagnostic_output
    generation = Path(latest["run_path"])
    assert generation.parent == (scan_logs / "runs").resolve(), diagnostic_output
    output = generation / "scan_results.json"
    assert output.exists(), diagnostic_output
    assert (generation / "report_manifest.json").is_file(), diagnostic_output
    loaded = json.loads(output.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _forensic_projection(results: dict[str, object], corpus: Path) -> dict[str, object]:
    projected: dict[str, object] = {}
    for key, value in results.items():
        assert isinstance(value, dict)
        rel = Path(str(key)).resolve().relative_to(corpus.resolve()).as_posix()
        projected[rel] = {
            "verdict": value.get("verdict"),
            "tags": value.get("tags", ()),
            "chains": value.get("chains", ()),
            "detected_engine": value.get("detected_engine"),
            "fingerprint_evidence": value.get("fingerprint_evidence", ()),
            "baseline_key": value.get("baseline_key"),
            "classification": value.get("classification"),
            "exit_code": value.get("exit_code"),
        }
    return projected


def test_stage359_governance_snapshot_is_recursively_immutable_and_digest_stable() -> None:
    left = make_governance_snapshot(
        queue_state={"pending": ["b.bin", "a.bin"], "nested": {"z": 2, "a": 1}},
        scheduler_decisions=[{"worker": 2, "path": "b.bin"}, {"path": "a.bin", "worker": 1}],
    )
    right = make_governance_snapshot(
        queue_state={"nested": {"a": 1, "z": 2}, "pending": ["a.bin", "b.bin"]},
        scheduler_decisions=[{"worker": 1, "path": "a.bin"}, {"worker": 2, "path": "b.bin"}],
    )
    assert left.stable_digest() == right.stable_digest()
    with pytest.raises(TypeError):
        left.queue_state["new"] = "mutation"  # type: ignore[index]
    with pytest.raises(TypeError):
        left.queue_state["nested"]["new"] = "mutation"  # type: ignore[index]


def test_stage359_path_inventory_is_stable_and_artifact_exclusion_is_enforced(tmp_path: Path) -> None:
    (tmp_path / "B" / "two.txt").parent.mkdir(parents=True)
    (tmp_path / "a" / "one.txt").parent.mkdir(parents=True)
    (tmp_path / "Scan Logs").mkdir()
    (tmp_path / "B" / "two.txt").write_text("2", encoding="utf-8")
    (tmp_path / "a" / "one.txt").write_text("1", encoding="utf-8")
    (tmp_path / "Scan Logs" / "scan_results.json").write_text("{}", encoding="utf-8")
    assert deterministic_path_inventory(tmp_path) == (
        "a/one.txt",
        "B/two.txt",
        "Scan Logs/scan_results.json",
    )
    assert should_include_scan_path(tmp_path / "Scan Logs" / "scan_results.json") is False
    assert should_include_scan_path(tmp_path / "B" / "two.txt") is True



def test_stage2064_cli_environment_does_not_inherit_pytest_or_umige_state() -> None:
    os.environ["UMIGE_STAGE2064_LEAK"] = "should-not-propagate"
    os.environ["PYTEST_CURRENT_TEST"] = "stage2064 sentinel"
    try:
        runtime_root = Path.cwd() / "stage2064_runtime_root"
        env = _isolated_cli_environment(runtime_root)
    finally:
        os.environ.pop("UMIGE_STAGE2064_LEAK", None)
        os.environ.pop("PYTEST_CURRENT_TEST", None)

    assert "UMIGE_STAGE2064_LEAK" not in env
    assert "PYTEST_CURRENT_TEST" not in env
    assert env["PYTHONDONTWRITEBYTECODE"] == "1"
    assert env["UMIGE_BASE_DIR"] == str(runtime_root.resolve())
    assert str(ROOT.parent) in env["PYTHONPATH"].split(os.pathsep)



def test_stage2068_live_scan_integration_uses_single_runtime_child_process() -> None:
    source = Path(__file__).read_text(encoding="utf-8")
    runtime_entrypoint = "Virus_Scan" + ".runtime_main"
    startup_entrypoint = "Virus_Scan" + ".main"
    assert f'"{runtime_entrypoint}"' in source
    assert f'"{startup_entrypoint}"' not in source

def test_stage359_serial_and_process_cli_scans_have_equivalent_forensic_json(tmp_path: Path) -> None:
    corpus = _write_corpus(tmp_path)
    serial = _run_cli(corpus, tmp_path / "serial_out", scheduler="serial")
    process = _run_cli(corpus, tmp_path / "process_out", scheduler="process")
    assert deterministic_json_digest(_forensic_projection(serial, corpus)) == deterministic_json_digest(_forensic_projection(process, corpus))
    assert validate_runtime_cleanup(context="stage359_after_cli") is True


def test_stage359_scan_root_does_not_rescan_runtime_output_artifacts(tmp_path: Path) -> None:
    """Lock scheduler target collection without a second live CLI subprocess.

    The Stage 359 file already performs a live serial/process CLI comparison in
    ``test_stage359_serial_and_process_cli_scans_have_equivalent_forensic_json``.
    This assertion is specifically about target collection: generated runtime
    outputs under a scan root must never become scheduler inputs.  Exercising the
    scheduler collection contract directly keeps the test deterministic and
    avoids a timeout-prone second CLI scan over a directory that is also being
    used as the output location.
    """
    corpus = _write_corpus(tmp_path)
    output_root = tmp_path / "Scan Logs"
    output_root.mkdir()
    generated_artifacts = (
        output_root / "scan_results.json",
        output_root / "scan_results.json.partial",
        output_root / "scanlog",
        output_root / "virustotal_results.json",
    )
    for artifact in generated_artifacts:
        artifact.write_text("{}", encoding="utf-8")
        assert should_include_scan_path(artifact, scan_root=tmp_path) is False

    collected = tuple(Path(path).resolve() for path in collect_scheduler_target_files(str(tmp_path)))
    expected = tuple(sorted(path.resolve() for path in corpus.rglob("*") if path.is_file()))

    assert tuple(sorted(collected)) == expected
    for path in collected:
        lowered = path.as_posix().lower()
        assert "/scan logs/" not in lowered
        assert "scan_results.json" not in lowered
        assert "virustotal_results.json" not in lowered
        assert "scanlog" not in lowered
