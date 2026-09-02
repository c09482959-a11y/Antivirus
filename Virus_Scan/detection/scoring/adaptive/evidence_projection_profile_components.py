from __future__ import annotations

from collections.abc import Callable, Mapping

from Virus_Scan.detection.scoring.adaptive.confidence import (
    coerce_model_probability,
    finite_engine_context,
    model_signal_unavailable_reason,
)
from Virus_Scan.detection.scoring.adaptive.public_inputs import adaptive_public_mapping
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.api import log_error

def engine_profile_probability_components(
    tags: object,
    file_context: object,
    file_context_reason: str | None,
    strings_blob: object,
    api_calls: object,
    ordered_events: object,
    *,
    infer_engine_context_fn: Callable[..., Mapping[str, object]],
    model_extension_profile_anomaly_fn: Callable[..., Mapping[str, object]],
    model_coordinated_validation_signal_fn: Callable[..., Mapping[str, object]],
) -> tuple[float, float, float, float, str | None, str | None, str | None, str | None]:
    try:
        if file_context_reason is not None:
            raise ValueError('adaptive_probability_file_context_coercion_failed')
        engine_ctx = infer_engine_context_fn(tags, file_structure=file_context, strings_blob=strings_blob)
        finite_engine_ctx, engine_value_reason = finite_engine_context(engine_ctx)
        p_engine = max(finite_engine_ctx.values()) if finite_engine_ctx else 0.0
        p_engine_reason = engine_value_reason or None
        if not engine_ctx:
            p_engine_reason = 'engine_context_unavailable'
        engine = (
            max(tuple(finite_engine_ctx), key=lambda name: finite_engine_ctx[name])
            if finite_engine_ctx
            else 'other'
        )
        profile_a = model_extension_profile_anomaly_fn(
            engine,
            file_context,
            tags,
            0.0,
            strings_blob=strings_blob,
            api_calls=api_calls,
            ordered_events=ordered_events,
        )
        p_profile, profile_value_reason = coerce_model_probability(
            profile_a.get('anomaly', 0.0),
            'non_finite_profile_probability',
        )
        model_a = model_coordinated_validation_signal_fn(
            engine,
            file_context,
            tags,
            strings_blob=strings_blob,
            api_calls=api_calls,
            ordered_events=ordered_events,
        )
        bucket_validation = adaptive_public_mapping(model_a.get('bucket_validation'))
        vector_validation = adaptive_public_mapping(model_a.get('vector_validation'))
        p_bucket, bucket_value_reason = coerce_model_probability(
            bucket_validation.get('bucket_anomaly', 0.0),
            'non_finite_bucket_probability',
        )
        p_vector, vector_value_reason = coerce_model_probability(
            vector_validation.get('anomaly', 0.0),
            'non_finite_vector_probability',
        )
        return (
            p_engine,
            p_profile,
            p_bucket,
            p_vector,
            p_engine_reason,
            model_signal_unavailable_reason(profile_a) or profile_value_reason,
            model_signal_unavailable_reason(bucket_validation) or bucket_value_reason,
            model_signal_unavailable_reason(vector_validation) or vector_value_reason,
        )
    except RECOVERABLE_RUNTIME_ERRORS:
        log_error('model probability component failed without synthetic substitute')
        return (
            0.0,
            0.0,
            0.0,
            0.0,
            'engine_context_probability_failed',
            'profile_probability_failed',
            'bucket_probability_failed',
            'vector_probability_failed',
        )

