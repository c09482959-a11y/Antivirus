"""Offline read-only Enterprise ATT&CK capability-gap analyzer."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from Virus_Scan.detection.attack.gap_analysis import build_attack_capability_gap_report
from Virus_Scan.detection.attack.integrity import git_blob_sha1_bytes, sha256_bytes
from Virus_Scan.detection.attack.stix_importer import import_stix_bundle

_MAX_BUNDLE_BYTES = 256 * 1024 * 1024


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", help="Validated external enterprise-attack.json path")
    parser.add_argument("--expected-git-blob-sha1", required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--output", type=Path)
    return parser


def _read_bundle(value: str) -> bytes:
    if type(value) is not str or not value:
        raise TypeError("attack_gap_bundle_path_invalid")
    path = Path(str.__str__(value))
    if not path.is_file():
        raise ValueError("attack_gap_bundle_missing")
    size = path.stat().st_size
    if size < 2 or size > _MAX_BUNDLE_BYTES:
        raise ValueError("attack_gap_bundle_size_invalid")
    return path.read_bytes()


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    payload = _read_bundle(arguments.bundle)
    computed = git_blob_sha1_bytes(payload)
    snapshot = import_stix_bundle(
        payload,
        dataset_version=arguments.expected_git_blob_sha1,
        source_ref=arguments.source_ref,
        expected_git_blob_sha1=arguments.expected_git_blob_sha1,
        computed_git_blob_sha1=computed,
        local_sha256=sha256_bytes(payload),
    )
    report = build_attack_capability_gap_report(snapshot)
    encoded = json.dumps(
        report.to_record(), sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )
    if arguments.output is None:
        sys.stdout.write(encoded + "\n")
    else:
        arguments.output.write_text(encoded + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
