"""Canonical package-level entrypoint for UMIGE engine routing.

The full-tree forensic validation imports this subsystem by a concise package
path. Routing ownership remains in ``Virus_Scan.routing`` modules; this file
publishes the stable routing surface with direct imports and no runtime
branching, hidden state hydration, or secondary execution behavior.
"""
from Virus_Scan.routing.artifact_fingerprints import ArtifactFingerprint
from Virus_Scan.routing.artifact_fingerprints import fingerprint_artifact
from Virus_Scan.routing.baseline_routing import BaselineRoute, BaselineRouteRequest
from Virus_Scan.routing.baseline_routing import build_baseline_route
from Virus_Scan.routing.baseline_routing import effective_analysis_engine
from Virus_Scan.routing.context_identity import EngineContextIdentity
from Virus_Scan.routing.context_identity import classify_engine_context
from Virus_Scan.routing.engine_detect import detect_target_engine_context
from Virus_Scan.routing.engine_detect import engine_confidence_report
from Virus_Scan.routing.engine_detect import engine_extension_key
from Virus_Scan.routing.engine_detect import infer_engine_context
from Virus_Scan.routing.engine_detect import infer_profile_engine
from Virus_Scan.routing.engine_detect import resolve_scan_engine_hint
from Virus_Scan.routing.engine_fingerprints import EngineFingerprint
from Virus_Scan.routing.engine_fingerprints import choose_engine
from Virus_Scan.routing.engine_fingerprints import fingerprint_container
from Virus_Scan.routing.engine_fingerprints import score_engine_for_path
from Virus_Scan.routing.file_identity import FileIdentity
from Virus_Scan.routing.file_identity import artifact_engine_from_identity
from Virus_Scan.routing.file_identity import sniff_file_identity
from Virus_Scan.routing.magic import MagicRouter

__all__ = (
    "ArtifactFingerprint",
    "BaselineRoute",
    "BaselineRouteRequest",
    "EngineContextIdentity",
    "EngineFingerprint",
    "FileIdentity",
    "MagicRouter",
    "artifact_engine_from_identity",
    "build_baseline_route",
    "choose_engine",
    "classify_engine_context",
    "detect_target_engine_context",
    "effective_analysis_engine",
    "engine_confidence_report",
    "engine_extension_key",
    "fingerprint_artifact",
    "fingerprint_container",
    "infer_engine_context",
    "infer_profile_engine",
    "resolve_scan_engine_hint",
    "score_engine_for_path",
    "sniff_file_identity",
)
