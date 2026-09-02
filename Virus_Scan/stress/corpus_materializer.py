"""Safe deterministic materialization of inert-malicious stress fixtures."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict
from pathlib import Path
import tempfile

from Virus_Scan.runtime.api import (
    durable_replace_regular_file,
    flush_open_writable_file,
    path_contains_filesystem_alias,
)
from Virus_Scan.stress.corpus_types import (
    MaliciousCorpusManifest,
    MaterializedMaliciousCorpus,
    MaterializedMaliciousSample,
)
from Virus_Scan.stress.malicious_corpus import build_malicious_oracle_manifest, inert_malicious_sample_bytes


def _path(value: object, *, reason: str) -> Path:
    if type(value) is str:
        return Path(str.__str__(value))
    if isinstance(value, Path) and type(value).__module__.startswith("pathlib"):
        return Path(value)
    raise TypeError(reason)


def malicious_manifest_to_json(manifest: MaliciousCorpusManifest) -> dict[str, object]:
    return {
        "schema_version": manifest.schema_version,
        "run_id": manifest.run_id,
        "total_samples": manifest.total_samples,
        "cases": [asdict(case) for case in manifest.cases],
    }


def _write_atomic_json(target: Path, payload: object) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=target.name + ".",
        suffix=".tmp",
        dir=str(target.parent),
        text=True,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
            stream.write("\n")
            stream.flush()
            flush_open_writable_file(stream.fileno())
        durable_replace_regular_file(Path(temporary_name), target)
    except (OSError, TypeError, ValueError):
        Path(temporary_name).unlink(missing_ok=True)
        raise


def write_malicious_oracle_manifest(path: object, manifest: MaliciousCorpusManifest) -> str:
    target = _path(path, reason="malicious_manifest_path_rejected").absolute()
    if path_contains_filesystem_alias(target.parent):
        raise ValueError("malicious_manifest_path_rejected")
    _write_atomic_json(target, malicious_manifest_to_json(manifest))
    return str(target)


def _ensure_empty_corpus_root(root: Path) -> None:
    if path_contains_filesystem_alias(root.parent):
        raise ValueError("malicious_corpus_root_rejected")
    if root.exists() and (
        path_contains_filesystem_alias(root) or not root.is_dir()
    ):
        raise ValueError("malicious_corpus_root_rejected")
    root.mkdir(parents=True, exist_ok=True)
    if next(root.iterdir(), None) is not None:
        raise ValueError("malicious_corpus_root_not_empty")


def _materialize_case(root: Path, case: object) -> MaterializedMaliciousSample:
    destination = (root / case.relative_path).absolute()
    if not destination.is_relative_to(root) or destination == root:
        raise ValueError("malicious_corpus_path_escape")
    if path_contains_filesystem_alias(destination.parent):
        raise ValueError("malicious_corpus_path_escape")
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = inert_malicious_sample_bytes(case.sample_id, case.family, case.index)
    with destination.open("xb") as stream:
        stream.write(payload)
    if path_contains_filesystem_alias(destination) or not destination.is_file():
        raise ValueError("malicious_corpus_nonregular_sample")
    raw = destination.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if len(raw) != case.size_bytes or digest != case.sha256:
        raise ValueError("malicious_corpus_materialization_mismatch")
    return MaterializedMaliciousSample(
        sample_id=case.sample_id,
        relative_path=case.relative_path,
        absolute_path=str(destination),
        size_bytes=len(raw),
        sha256=digest,
    )


def materialize_malicious_corpus(
    root: object,
    count: int = 10_000,
    *,
    manifest_path: object = None,
    run_id: str = "stage2636-malicious",
) -> MaterializedMaliciousCorpus:
    target_root = _path(root, reason="malicious_corpus_root_path_rejected").absolute()
    _ensure_empty_corpus_root(target_root)
    manifest = build_malicious_oracle_manifest(count, run_id=run_id)
    samples = tuple(_materialize_case(target_root, case) for case in manifest.cases)
    target_manifest = (
        target_root.parent / "manifests" / "malicious_manifest.json"
        if manifest_path is None
        else _path(manifest_path, reason="malicious_manifest_path_rejected").absolute()
    )
    if target_manifest.is_relative_to(target_root):
        raise ValueError("malicious_manifest_inside_corpus_rejected")
    written_manifest = write_malicious_oracle_manifest(target_manifest, manifest)
    return MaterializedMaliciousCorpus(str(target_root), written_manifest, samples)


__all__ = (
    "malicious_manifest_to_json",
    "materialize_malicious_corpus",
    "write_malicious_oracle_manifest",
)
