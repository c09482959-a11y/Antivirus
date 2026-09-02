"""Scan-owned incremental recovery-record cache for partial checkpoints."""
from __future__ import annotations

from dataclasses import dataclass, field

from Virus_Scan.contracts.checkpoint import JsonSafeCheckpointDelta, checkpoint_key_text
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items


@dataclass(slots=True)
class PartialCheckpointCache:
    """Materialize each terminal recovery record once and retain one pending delta."""

    source_identities: dict[str, int] = field(default_factory=dict)
    pending_records: dict[str, object] = field(default_factory=dict)
    committed_records: int = 0

    def observe_terminal(self, key: object, value: object, make_json_safe: object) -> bool:
        key_text, reason = checkpoint_key_text(key)
        if reason:
            raise TypeError("checkpoint_terminal_key_rejected:" + reason)
        identity = id(value)
        previous = dict.get(self.source_identities, key_text)
        if previous is not None:
            if previous != identity:
                raise RuntimeError("checkpoint_terminal_record_replaced:" + key_text)
            return False
        if not callable(make_json_safe):
            raise TypeError("checkpoint_json_materializer_required")
        safe = make_json_safe(value)
        self.source_identities[key_text] = identity
        self.pending_records[key_text] = safe
        return True

    def observe_latest_terminal(self, results: object, make_json_safe: object) -> bool:
        """Observe the newest exact-dict terminal result in constant time."""
        if type(results) is not dict:
            raise TypeError("checkpoint_results_exact_dict_required")
        if not results:
            return False
        key = next(reversed(results))
        return self.observe_terminal(key, dict.__getitem__(results, key), make_json_safe)

    def reconcile_results(self, results: object, make_json_safe: object) -> int:
        """Observe terminal records missed by exceptional parent-side branches."""
        items = no_hook_mapping_items(results, allow_dict_subclass=True)
        if items is None:
            raise TypeError("checkpoint_results_mapping_required")
        observed = 0
        active: set[str] = set()
        for key, value in items:
            key_text, reason = checkpoint_key_text(key)
            if reason:
                raise TypeError("checkpoint_terminal_key_rejected:" + reason)
            active.add(key_text)
            if self.observe_terminal(key_text, value, make_json_safe):
                observed += 1
        missing = tuple(key for key in self.source_identities if key not in active)
        if missing:
            raise RuntimeError("checkpoint_terminal_record_removed:" + missing[0])
        return observed

    def pending_delta(self) -> JsonSafeCheckpointDelta:
        ordered = tuple(
            sorted(
                dict.items(self.pending_records),
                key=lambda item: item[0].replace("\\", "/").casefold(),
            )
        )
        return JsonSafeCheckpointDelta(
            ordered,
            self.committed_records + 1,
            self.committed_records + len(ordered),
        )

    def commit_delta(self, delta: JsonSafeCheckpointDelta) -> None:
        if type(delta) is not JsonSafeCheckpointDelta:
            raise TypeError("checkpoint_delta_required")
        expected = self.pending_delta()
        if delta is not expected and delta != expected:
            raise RuntimeError("checkpoint_delta_commit_mismatch")
        for key, _record in delta.items:
            del self.pending_records[key]
        self.committed_records = delta.total_records


__all__ = ("PartialCheckpointCache",)
