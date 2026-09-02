"""Centroid mutation is owned exclusively by the canonical assignment transaction.

The previous public updater accepted arbitrary dimensions, padded vectors, and
mutated a derived signature index independently of cluster metadata. That path
is intentionally removed; ``microcluster_update.update_microcluster_snapshot`` is the
single update primitive and is committed only by the assignment transaction or
canonical persistence hydration.
"""

__all__: tuple[str, ...] = ()
