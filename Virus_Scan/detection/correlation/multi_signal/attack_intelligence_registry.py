"""Validated immutable classifier registry for attack intelligence."""
from __future__ import annotations

import hashlib
import json

from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_contracts import AttackClassifierSpec
from Virus_Scan.detection.tags.heuristics.credential_chains import detect_lolbin_credential_theft
from Virus_Scan.detection.tags.heuristics.evasion_classifier import classify_defense_evasion
from Virus_Scan.detection.tags.heuristics.execution_classifiers import (
    classify_bytecode_and_script,
    classify_dotnet_behavior,
    classify_fileless_loader,
    classify_packed_dropper,
)
from Virus_Scan.detection.tags.heuristics.movement_exfiltration import (
    classify_exfiltration,
    classify_lateral_movement,
)


def _spec(
    classifier_id: str,
    family: str,
    detector: object,
    ceiling: float,
    slope: float,
    midpoint: float,
    threshold: float,
) -> AttackClassifierSpec:
    return AttackClassifierSpec(
        classifier_id=classifier_id,
        version="attack_classifier_v3",
        family=family,
        detector=detector,
        score_ceiling=ceiling,
        calibration_slope=slope,
        calibration_midpoint=midpoint,
        production_threshold=threshold,
    )


ATTACK_INTELLIGENCE_CLASSIFIERS = (
    _spec("lateral_movement", "lateral_movement", classify_lateral_movement, 30.0, 8.0, 0.34, 0.52),
    _spec("defense_evasion", "defense_evasion", classify_defense_evasion, 30.0, 8.5, 0.32, 0.50),
    _spec("exfiltration", "exfiltration", classify_exfiltration, 25.0, 8.0, 0.34, 0.52),
    _spec("packed_dropper", "packed_dropper", classify_packed_dropper, 32.0, 7.5, 0.38, 0.54),
    _spec("fileless_loading", "fileless_loading", classify_fileless_loader, 32.0, 8.0, 0.35, 0.53),
    _spec("bytecode_scripts", "bytecode_scripts", classify_bytecode_and_script, 22.0, 7.5, 0.36, 0.54),
    _spec("dotnet_behavior", "dotnet_behavior", classify_dotnet_behavior, 22.0, 7.0, 0.40, 0.56),
    _spec("credential_theft", "credential_theft", detect_lolbin_credential_theft, 26.0, 8.5, 0.30, 0.50),
)


ATTACK_INTELLIGENCE_CLASSIFIER_REGISTRY_VERSION = "attack_classifier_registry_v3"


def attack_intelligence_classifier_registry_manifest() -> dict[str, object]:
    """Return the deterministic semantic identity of the classifier registry."""
    records = tuple({
        "classifier_id": spec.classifier_id,
        "version": spec.version,
        "family": spec.family,
        "detector_module": spec.detector.__module__,
        "detector_name": spec.detector.__name__,
        "score_ceiling": spec.score_ceiling,
        "calibration_slope": spec.calibration_slope,
        "calibration_midpoint": spec.calibration_midpoint,
        "production_threshold": spec.production_threshold,
        "minimum_distinct_roots": spec.minimum_distinct_roots,
        "minimum_direct_roots": spec.minimum_direct_roots,
        "required_evidence_kinds": tuple(sorted(spec.required_evidence_kinds)),
    } for spec in ATTACK_INTELLIGENCE_CLASSIFIERS)
    payload = {
        "version": ATTACK_INTELLIGENCE_CLASSIFIER_REGISTRY_VERSION,
        "records": records,
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return {**payload, "digest": hashlib.sha256(encoded).hexdigest()}


ATTACK_INTELLIGENCE_CLASSIFIER_REGISTRY_MANIFEST = (
    attack_intelligence_classifier_registry_manifest()
)
ATTACK_INTELLIGENCE_CLASSIFIER_REGISTRY_DIGEST = (
    ATTACK_INTELLIGENCE_CLASSIFIER_REGISTRY_MANIFEST["digest"]
)


def _validate_registry() -> None:
    ids = tuple(spec.classifier_id for spec in ATTACK_INTELLIGENCE_CLASSIFIERS)
    families = tuple(spec.family for spec in ATTACK_INTELLIGENCE_CLASSIFIERS)
    if len(ids) != len(set(ids)):
        raise RuntimeError("attack_classifier_id_duplicate")
    if len(families) != len(set(families)):
        raise RuntimeError("attack_classifier_family_duplicate")


_validate_registry()

__all__ = (
    "ATTACK_INTELLIGENCE_CLASSIFIERS",
    "ATTACK_INTELLIGENCE_CLASSIFIER_REGISTRY_DIGEST",
    "ATTACK_INTELLIGENCE_CLASSIFIER_REGISTRY_MANIFEST",
    "ATTACK_INTELLIGENCE_CLASSIFIER_REGISTRY_VERSION",
    "attack_intelligence_classifier_registry_manifest",
)
