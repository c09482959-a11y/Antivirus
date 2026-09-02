"""Immutable evaluated policy for the canonical attack-intelligence ensemble."""
from types import MappingProxyType

from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_contracts import (
    AttackEnsemblePolicy,
)

ATTACK_INTELLIGENCE_AGGREGATE_VERSION = "attack_intelligence_noisy_or_v1"
ATTACK_INTELLIGENCE_CALIBRATION_VERSION = "stage2636_11020_atomic_family_calibration_v2"
ATTACK_INTELLIGENCE_YARA_MAPPING_VERSION = "attack_yara_family_mapping_v1"

ATTACK_ENSEMBLE_POLICY = AttackEnsemblePolicy(
    version="attack_intelligence_policy_v3",
    aggregate_method=ATTACK_INTELLIGENCE_AGGREGATE_VERSION,
    calibration_version=ATTACK_INTELLIGENCE_CALIBRATION_VERSION,
    yara_corroboration_bonus=0.08,
    maximum_records=32,
    evaluation_provenance="stage2636_11020_atomic_family_holdout_v3",
    yara_mapping_version=ATTACK_INTELLIGENCE_YARA_MAPPING_VERSION,
    aggregate_threshold=0.5,
)
ATTACK_ENSEMBLE_POLICY_RECORD = MappingProxyType({
    "version": ATTACK_ENSEMBLE_POLICY.version,
    "aggregate_method": ATTACK_ENSEMBLE_POLICY.aggregate_method,
    "calibration_version": ATTACK_ENSEMBLE_POLICY.calibration_version,
    "yara_corroboration_bonus": ATTACK_ENSEMBLE_POLICY.yara_corroboration_bonus,
    "maximum_records": ATTACK_ENSEMBLE_POLICY.maximum_records,
    "evaluation_provenance": ATTACK_ENSEMBLE_POLICY.evaluation_provenance,
    "yara_mapping_version": ATTACK_ENSEMBLE_POLICY.yara_mapping_version,
    "aggregate_threshold": ATTACK_ENSEMBLE_POLICY.aggregate_threshold,
})

__all__ = (
    "ATTACK_ENSEMBLE_POLICY", "ATTACK_ENSEMBLE_POLICY_RECORD",
    "ATTACK_INTELLIGENCE_AGGREGATE_VERSION",
    "ATTACK_INTELLIGENCE_CALIBRATION_VERSION",
    "ATTACK_INTELLIGENCE_YARA_MAPPING_VERSION",
)
