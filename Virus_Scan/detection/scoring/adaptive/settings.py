from collections.abc import Mapping
from types import MappingProxyType

from Virus_Scan.detection.registries.immutability import freeze_registry_value
from Virus_Scan.runtime.api import runtime_value


def runtime_mapping(name: str, default: Mapping[str, object]) -> MappingProxyType:
    value = runtime_value(name, default)
    if type(value) is dict or isinstance(value, MappingProxyType):
        return freeze_registry_value(value)
    return freeze_registry_value(default)


ADAPTIVE_WEIGHT_BOUNDS = runtime_mapping('ADAPTIVE_WEIGHT_BOUNDS', {})
ADAPTIVE_WEIGHT_MIN_HISTORY = int(runtime_value('ADAPTIVE_WEIGHT_MIN_HISTORY', 5))
ADAPTIVE_LEARNED_MODEL_STATIC_VERSION = str(runtime_value('ADAPTIVE_LEARNED_MODEL_STATIC_VERSION', 'adaptive_learned_model_static_v1'))
ADAPTIVE_LEARNED_MODEL_MIN_WEIGHT = float(runtime_value('ADAPTIVE_LEARNED_MODEL_MIN_WEIGHT', 0.15))
ADAPTIVE_LEARNED_MODEL_MAX_WEIGHT = float(runtime_value('ADAPTIVE_LEARNED_MODEL_MAX_WEIGHT', 0.8))
ADAPTIVE_LEARNED_MODEL_WEAK_EVIDENCE_CAP = float(runtime_value('ADAPTIVE_LEARNED_MODEL_WEAK_EVIDENCE_CAP', 0.25))
ADAPTIVE_LEARNED_MODEL_SINGLE_ANCHOR_CAP = float(runtime_value('ADAPTIVE_LEARNED_MODEL_SINGLE_ANCHOR_CAP', 0.45))
ADAPTIVE_LEARNED_MODEL_IMMATURE_CAP = float(runtime_value('ADAPTIVE_LEARNED_MODEL_IMMATURE_CAP', 0.35))
ADAPTIVE_LEARNED_MODEL_CONTRADICTION_CAP = float(runtime_value('ADAPTIVE_LEARNED_MODEL_CONTRADICTION_CAP', 0.2))
CALIBRATED_SCORE_VERSION = str(runtime_value('CALIBRATED_SCORE_VERSION', 'calibrated_score_v1'))
CALIBRATED_SCORE_THRESHOLDS = runtime_mapping('CALIBRATED_SCORE_THRESHOLDS', {'low': 25.0, 'high': 50.0, 'malicious': 75.0})
LAYER_WEIGHTS = runtime_mapping('LAYER_WEIGHTS', {'quick_static': 0.25, 'threat_intel': 0.25, 'graph': 0.20, 'timeline': 0.15, 'context': 0.15})
ADAPTIVE_WEIGHT_VERSION = str(runtime_value('ADAPTIVE_WEIGHT_VERSION', 'adaptive_weight_v1'))
ADAPTIVE_PROBABILITY_FEATURE_BUNDLE_VERSION = 'adaptive_probability_features_v2'


__all__ = (
    'ADAPTIVE_LEARNED_MODEL_CONTRADICTION_CAP',
    'ADAPTIVE_LEARNED_MODEL_IMMATURE_CAP',
    'ADAPTIVE_LEARNED_MODEL_MAX_WEIGHT',
    'ADAPTIVE_LEARNED_MODEL_MIN_WEIGHT',
    'ADAPTIVE_LEARNED_MODEL_SINGLE_ANCHOR_CAP',
    'ADAPTIVE_LEARNED_MODEL_STATIC_VERSION',
    'ADAPTIVE_LEARNED_MODEL_WEAK_EVIDENCE_CAP',
    'ADAPTIVE_PROBABILITY_FEATURE_BUNDLE_VERSION',
    'ADAPTIVE_WEIGHT_BOUNDS',
    'ADAPTIVE_WEIGHT_MIN_HISTORY',
    'ADAPTIVE_WEIGHT_VERSION',
    'CALIBRATED_SCORE_THRESHOLDS',
    'CALIBRATED_SCORE_VERSION',
    'LAYER_WEIGHTS',
    'runtime_mapping',
)
