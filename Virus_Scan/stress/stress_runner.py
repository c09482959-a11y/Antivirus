"""Canonical real-lifecycle runner for isolated inert-malicious stress gates."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from Virus_Scan.stress.corpus_materializer import materialize_malicious_corpus
from Virus_Scan.stress.corpus_policy import INERT_MALICIOUS_STRESS_SAMPLES
from Virus_Scan.stress.profile_verifier import snapshot_profiles
from Virus_Scan.stress.run_verifier import verify_stress_run


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m Virus_Scan.stress.stress_runner")
    parser.add_argument("--root", required=True)
    parser.add_argument("--count", type=int, default=1_000)
    parser.add_argument("--scheduler", choices=("serial", "process"), default="serial")
    parser.add_argument("--workers", type=int, default=1)
    return parser


def _prepare_root(root: Path) -> None:
    if root.exists() and (not root.is_dir() or next(root.iterdir(), None) is not None):
        raise ValueError("stress_root_must_be_new_or_empty")
    root.mkdir(parents=True, exist_ok=True)
    for relative in ("Scan Logs", "profiles", "Temp", "Yara", "Mitre", "VirusTotal", "manifests", "audit"):
        (root / relative).mkdir(parents=True, exist_ok=True)


def _write_local_yara_rule(root: Path) -> Path:
    target = root / "Yara" / "stage2636_inert_stress.yar"
    target.write_text(
        'rule UMIGE_Inert_Malicious_Stress { strings: $marker = "UMIGE INERT MALICIOUS STRESS SAMPLE" condition: $marker }\n',
        encoding="utf-8",
    )
    return target


def _scanner_command(root: Path, scheduler: str, workers: int, count: int, yara_rule: Path) -> tuple[str, ...]:
    checkpoint_every = min(100, count)
    return (
        sys.executable, "-m", "Virus_Scan.runtime_main",
        "--dir", str(root / "corpus"),
        "--scheduler", scheduler,
        "--workers", str(workers),
        "--yara", str(yara_rule),
        "--yara-no-download", "--no-yaralight",
        "--no-scan-cache", "--deep-scan-mode", "thorough",
        "--scan-log-root", str(root / "Scan Logs"),
        "--partial-output-every", str(checkpoint_every),
        "--progress-every", str(checkpoint_every),
        "--profile-corruption-policy", "hard-fail",
    )


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def run_stress(root: Path, *, count: int, scheduler: str, workers: int) -> int:
    if type(count) is not int or count < 1 or count > INERT_MALICIOUS_STRESS_SAMPLES:
        raise ValueError("stress_count_out_of_range")
    if type(workers) is not int or workers < 1:
        raise ValueError("stress_worker_count_out_of_range")
    _prepare_root(root)
    run_id = "stage2636-" + scheduler + "-" + str(count)
    materialized = materialize_malicious_corpus(
        root / "corpus",
        count,
        manifest_path=root / "manifests" / "malicious_manifest.json",
        run_id=run_id,
    )
    _write_json(root / "audit" / "profile_before.json", asdict(snapshot_profiles(root / "profiles")))
    command = _scanner_command(root, scheduler, workers, count, _write_local_yara_rule(root))
    environment = dict(os.environ)
    environment["UMIGE_BASE_DIR"] = str(root.resolve())
    environment["PYTHONPATH"] = str(Path.cwd().resolve())
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    started = time.monotonic()
    with (root / "audit" / "scanner_stdout.log").open("w", encoding="utf-8") as stream:
        completed = subprocess.run(command, cwd=Path.cwd(), env=environment, stdout=stream, stderr=subprocess.STDOUT, check=False)
    verification = verify_stress_run(root, expected_count=count, scanner_exit_code=completed.returncode)
    payload = asdict(verification)
    payload["elapsed_seconds"] = round(time.monotonic() - started, 6)
    payload["command"] = command
    payload["materialized_manifest_path"] = materialized.manifest_path
    _write_json(root / "audit" / "profile_after.json", asdict(snapshot_profiles(root / "profiles")))
    _write_json(root / "audit" / "verification.json", payload)
    return 0 if verification.passed else 1


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    return run_stress(Path(args.root).resolve(), count=args.count, scheduler=args.scheduler, workers=args.workers)


if __name__ == "__main__":
    raise SystemExit(main())
