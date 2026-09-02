"""Canonical per-artifact engine fingerprinting.

This module owns artifact-level engine selection by combining file identity
sniffing with path/content engine fingerprints. Container classification and
baseline routing consume this result directly so extension-only routing cannot
survive as a parallel path.
"""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.routing.engine_fingerprints import choose_engine, score_engine_for_path
from Virus_Scan.routing.file_identity import FileIdentity, artifact_engine_from_identity


@dataclass(frozen=True)
class ArtifactFingerprint:
    engine: str
    confidence: float
    evidence: tuple[str, ...]


def fingerprint_artifact(file_path: object, identity: FileIdentity, *, container_root: object | None = None) -> ArtifactFingerprint:
    """Return the canonical per-artifact engine fingerprint.

    Sniffed identity is authoritative for strong engine-specific formats and
    renamed binaries. Path fingerprints are used only when the identity is not
    decisive, preserving container context without restoring extension-only
    analyzer routing.
    """
    sniff_engine, sniff_conf, sniff_evidence = artifact_engine_from_identity(file_path, identity)
    identity_evidence = tuple(identity.evidence)
    if sniff_engine != "other" and sniff_conf >= 0.7:
        return ArtifactFingerprint(sniff_engine, sniff_conf, tuple(sniff_evidence) + identity_evidence)
    path_fp = choose_engine(score_engine_for_path(file_path, root=container_root))
    if sniff_engine != "other" and sniff_conf >= path_fp.confidence:
        return ArtifactFingerprint(sniff_engine, sniff_conf, tuple(sniff_evidence) + identity_evidence)
    if path_fp.engine != "other" and path_fp.confidence >= 0.5:
        return ArtifactFingerprint(path_fp.engine, path_fp.confidence, tuple(path_fp.evidence) + identity_evidence)
    return ArtifactFingerprint(sniff_engine, sniff_conf, tuple(sniff_evidence) + tuple(path_fp.evidence) + identity_evidence)
