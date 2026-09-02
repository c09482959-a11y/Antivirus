import math

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int
from Virus_Scan.models.clustering.common import (
    VECTOR_FEATURE_NAMES,
    cluster_finite_vector,
    cluster_mapping,
    cluster_text_sequence,
    finite_cluster_metric,
)

def _finite_vector_baseline_count(value: object) -> object:
    """Materialize a non-negative exact vector-baseline sample count."""
    count, reason = no_hook_exact_nonnegative_int(
        value,
        default=0,
        reason='unsafe_vector_baseline_count_rejected',
        non_finite_reason='non_finite_vector_baseline_count',
        allow_exact_text=True,
    )
    if reason:
        return 0
    return count


def _finite_vector_baseline_series(values: object, expected_len: object) -> object:
    """Materialize finite vector-baseline mean/M2 values without caller leaks."""
    raw_values = cluster_finite_vector(values)
    if len(raw_values) != expected_len:
        return ()
    return tuple(raw_values)


def online_vector_update(vector_baseline: object, vector: object, feature_names: object=None) -> object:
    """Return a new immutable-friendly vector baseline snapshot.

    The clustering model must not mutate a caller-owned profile baseline dict or
    retain caller-owned vector/list objects.  Consumers receive a fresh mapping
    with tuple materialized numeric fields; JSON writers can still serialize the
    tuple values as arrays, while subsequent updates can read them through
    ``list(...)`` without relying on mutability.
    """
    raw_feature_names = feature_names if feature_names is not None else VECTOR_FEATURE_NAMES
    feature_name_values, feature_name_reason = cluster_text_sequence(
        raw_feature_names,
        reason='cluster_feature_names_unavailable',
    )
    feature_names = tuple(feature_name_values if not feature_name_reason else VECTOR_FEATURE_NAMES)
    raw_vector = list(cluster_finite_vector(vector))
    clean_vector = []
    for item in raw_vector:
        value = finite_cluster_metric(item, 0.0)
        if not math.isfinite(value):
            value = 0.0
        clean_vector.append(value)
    source, _ = cluster_mapping(vector_baseline)
    n = _finite_vector_baseline_count(source.get('count', 0))
    mean = list(_finite_vector_baseline_series(source.get('mean', ()), len(clean_vector)))
    m2 = list(_finite_vector_baseline_series(source.get('m2', ()), len(clean_vector)))
    if n <= 0 or len(mean) != len(clean_vector) or len(m2) != len(clean_vector):
        mean = [0.0] * len(clean_vector)
        m2 = [0.0] * len(clean_vector)
        n = 0
    n += 1
    for i, x in enumerate(clean_vector):
        delta = x - mean[i]
        mean[i] += delta / n
        delta2 = x - mean[i]
        m2[i] += delta * delta2
    variance = tuple(m2[i] / max(1, n - 1) if n > 1 else 0.0 for i in range(len(clean_vector)))
    # This snapshot is persisted through profile/model JSON and must be
    # replay-deterministic.  Do not publish wall-clock time here: repeated
    # equivalent updates over identical inputs must materialize the same model
    # facts.  The monotonic update ordinal preserves the existing numeric
    # ``updated`` field for retention ranking without leaking live time.
    return {
        'count': n,
        'mean': tuple(mean),
        'm2': tuple(m2),
        'variance': variance,
        'feature_names': feature_names,
        'updated': float(n),
        'updated_source': 'deterministic_update_count',
    }
