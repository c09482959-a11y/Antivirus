"""Generate the inert Stage2636.11020 Phase 25 static-semantic corpus."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from Virus_Scan.detection.attack.integrity import git_blob_sha1_bytes, sha256_bytes
from Virus_Scan.detection.attack.stix_importer import import_stix_bundle
from Virus_Scan.stress.static_semantic_corpus import materialize_static_semantic_corpus

DEFAULT_BUNDLE = Path("Mitre/enterprise-attack.json")
DEFAULT_ROOT = Path("UMIGE_Static_Semantic_Evaluation_Corpus")


def generate(*, bundle_path: Path, corpus_root: Path) -> dict[str, object]:
    if type(bundle_path) is not type(DEFAULT_BUNDLE):
        raise TypeError("static_semantic_bundle_path_invalid")
    if type(corpus_root) is not type(DEFAULT_ROOT):
        raise TypeError("static_semantic_corpus_path_invalid")
    data = bundle_path.read_bytes()
    git_digest = git_blob_sha1_bytes(data)
    local_digest = sha256_bytes(data)
    snapshot = import_stix_bundle(
        data,
        dataset_version=git_digest,
        source_ref="stage2636.11020-phase25-static-semantic:enterprise-attack-v19.1",
        expected_git_blob_sha1=git_digest,
        computed_git_blob_sha1=git_digest,
        local_sha256=local_digest,
    )
    manifest = materialize_static_semantic_corpus(
        corpus_root, repository_digest=snapshot.digest,
    )
    return {
        "bundle_sha256": local_digest,
        "control_sample_count": manifest.control_sample_count,
        "corpus_evidence_class": manifest.corpus_evidence_class,
        "corpus_root": str(corpus_root),
        "coverage_path": str(corpus_root / "static_semantic_coverage_report.json"),
        "git_blob_sha1": git_digest,
        "generation_intent_path": str(corpus_root / "static_semantic_generation_intent_manifest.json"),
        "leakage_path": str(corpus_root / "static_semantic_leakage_report.json"),
        "malware_sample_count": manifest.malware_sample_count,
        "manifest_digest": manifest.digest,
        "manifest_path": str(corpus_root / "attack_evaluation_corpus_manifest.json"),
        "artifact_truth_path": str(corpus_root / "static_semantic_artifact_truth_manifest.json"),
        "artifact_truth_validation_path": str(corpus_root / "static_semantic_artifact_truth_validation.json"),
        "repository_digest": snapshot.digest,
        "safety_path": str(corpus_root / "static_semantic_safety_report.json"),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", default=str(DEFAULT_BUNDLE))
    parser.add_argument("--output-root", default=str(DEFAULT_ROOT))
    return parser


def main() -> int:
    args = _parser().parse_args()
    result = generate(
        bundle_path=Path(args.bundle),
        corpus_root=Path(args.output_root),
    )
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
