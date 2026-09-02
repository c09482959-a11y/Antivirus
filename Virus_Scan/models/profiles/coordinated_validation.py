"""Profile coordinated model-validation owner."""

import copy

from Virus_Scan.models.profiles.baseline import (
    ensure_extension_model_fields,
    get_extension_baseline,
    profile_behavior_bucket_validation,
)
from Virus_Scan.models.profiles.request_contracts import ProfileBucketValidationRequest
from Virus_Scan.models.profiles.vector_anomaly import vector_baseline_anomaly
from Virus_Scan.models.profiles.context import engine_extension_key
from Virus_Scan.models.profiles.learning import behavior_vector_from_scan
from Virus_Scan.models.profiles.timeline import extension_timeline_anomaly
from Virus_Scan.models.api.temporal_contracts import snapshot_temporal
from Virus_Scan.models.api.markov_contracts import compute_markov_features
from Virus_Scan.models.profiles.coordinated_unavailable import baseline_unavailable_reason, coordinated_validation_unavailable
from Virus_Scan.models.profiles.coordinated_validation_support import (
    coordinated_markov_support,
    coordinated_temporal_support,
    coordinated_timeline_validation,
    coordinated_validation_result,
    coordinated_vector_validation,
    ordered_events_unavailable_reason,
)
from Virus_Scan.runtime.init_state import get_init_value


BEHAVIOR_MODEL_VERSION = str(get_init_value('BEHAVIOR_MODEL_VERSION') or 'engine_extension_bucket_vector_v4')





def coordinated_model_validation_signal(engine: object, file_path: object, tags: object, risk: object=0.0, strings_blob: object='', api_calls: object=None, ordered_events: object=None) -> object:
    """Profile-owned coordinated model validation for adaptive extension scoring.

    Sub-model failures are output-affecting model evidence. They may suppress a
    single profile sub-signal to zero, but they must not make the coordinated
    model look clean or fully available.
    """
    baseline = copy.deepcopy(get_extension_baseline(engine, file_path))
    baseline_reason = baseline_unavailable_reason(baseline)
    if baseline_reason is not None:
        return coordinated_validation_unavailable(
            'coordinated_model_validation_failed',
            source_reason=baseline_reason,
        )
    ensure_extension_model_fields(baseline)
    unavailable_reasons: dict[str, object] = {}
    model_failures: list[object] = []
    ordered_reason = ordered_events_unavailable_reason(ordered_events)
    bucket_v = profile_behavior_bucket_validation(
        ProfileBucketValidationRequest(
            engine, file_path, tags, strings_blob, api_calls, ordered_events,
        )
    )
    vector_v = coordinated_vector_validation(
        engine,
        file_path,
        tags,
        risk,
        strings_blob,
        api_calls,
        ordered_events,
        baseline,
        ordered_reason,
        unavailable_reasons,
        model_failures,
        behavior_vector_from_scan,
        vector_baseline_anomaly,
    )
    temporal_boost = coordinated_temporal_support(
        file_path, unavailable_reasons, model_failures, snapshot_temporal,
    )
    markov_boost = coordinated_markov_support(
        file_path, tags, ordered_events, ordered_reason, unavailable_reasons,
        model_failures, compute_markov_features,
    )
    timeline_v = coordinated_timeline_validation(
        engine, file_path, tags, ordered_events, ordered_reason, unavailable_reasons,
        model_failures, extension_timeline_anomaly,
    )
    return coordinated_validation_result(
        model_version=BEHAVIOR_MODEL_VERSION,
        engine_extension=engine_extension_key(engine, file_path),
        bucket_v=bucket_v,
        vector_v=vector_v,
        timeline_v=timeline_v,
        temporal_boost=temporal_boost,
        markov_boost=markov_boost,
        unavailable_reasons=unavailable_reasons,
        model_failures=model_failures,
    )


__all__ = ('coordinated_model_validation_signal', 'coordinated_validation_unavailable')
