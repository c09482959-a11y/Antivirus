"""Generate the external inert Stage2636.11020 inert static-analysis challenge corpus."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from Virus_Scan.detection.attack.integrity import git_blob_sha1_bytes, sha256_bytes
from Virus_Scan.detection.attack.stix_importer import import_stix_bundle
from Virus_Scan.stress.attack_synthetic_corpus import (
    materialize_synthetic_attack_corpus,
)

DEFAULT_BUNDLE = Path("/mnt/data/Mitre/enterprise-attack.json")
DEFAULT_ROOT = Path("/mnt/data/UMIGE_Evaluation_Corpus")


def generate(*, bundle_path: Path, corpus_root: Path) -> dict[str, object]:
    if type(bundle_path) is not type(DEFAULT_BUNDLE):
        raise TypeError("synthetic_attack_bundle_path_invalid")
    if type(corpus_root) is not type(DEFAULT_ROOT):
        raise TypeError("synthetic_attack_corpus_path_invalid")
    data = bundle_path.read_bytes()
    git_digest = git_blob_sha1_bytes(data)
    local_digest = sha256_bytes(data)
    snapshot = import_stix_bundle(
        data,
        dataset_version=git_digest,
        source_ref="stage2636.11020-synthetic-challenge:enterprise-attack-v19.1",
        expected_git_blob_sha1=git_digest,
        computed_git_blob_sha1=git_digest,
        local_sha256=local_digest,
    )
    manifest = materialize_synthetic_attack_corpus(
        corpus_root, repository_digest=snapshot.digest,
    )
    return {
        "corpus_root": str(corpus_root),
        "manifest_path": str(corpus_root / "attack_evaluation_corpus_manifest.json"),
        "generation_intent_path": str(corpus_root / "synthetic_generation_intent_manifest.json"),
        "metadata_path": str(corpus_root / "synthetic_metadata_manifest.json"),
        "artifact_truth_path": str(corpus_root / "synthetic_artifact_truth_manifest.json"),
        "safety_path": str(corpus_root / "synthetic_safety_report.json"),
        "leakage_path": str(corpus_root / "synthetic_leakage_report.json"),
        "safe_trigger_path": str(corpus_root / "safe_yara_trigger_manifest.json"),
        "manifest_digest": manifest.digest,
        "corpus_evidence_class": manifest.corpus_evidence_class,
        "malware_sample_count": manifest.malware_sample_count,
        "control_sample_count": manifest.control_sample_count,
        "repository_digest": snapshot.digest,
        "bundle_sha256": local_digest,
        "git_blob_sha1": git_digest,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", default=str(DEFAULT_BUNDLE))
    parser.add_argument("--output-root", default=str(DEFAULT_ROOT))
    return parser


def main() -> int:
    args = _parser().parse_args()
    result = generate(
        bundle_path=Path(args.bundle), corpus_root=Path(args.output_root),
    )
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
