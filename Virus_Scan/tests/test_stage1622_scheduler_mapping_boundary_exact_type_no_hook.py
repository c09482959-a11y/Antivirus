from __future__ import annotations

import pytest

from Virus_Scan.scheduler.api.contracts import HybridQueueStateError
from Virus_Scan.scheduler.evidence.final_json_exact_fields import exact_mapping_items
from Virus_Scan.scheduler.evidence.record_collection import collect_scheduler_evidence, scheduler_evidence_mapping_items
from Virus_Scan.scheduler.internal.immutable_outputs import FrozenSchedulerMapping
from Virus_Scan.scheduler.replay.replay_result_fields import replay_mapping_items, replay_mapping_value
from Virus_Scan.scheduler.replay.replay_snapshot import validate_hybrid_counts


class HostileFrozenSchedulerMapping(FrozenSchedulerMapping):
    touched = 0

    @property
    def _items(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("do not call hostile _items")


def _hostile_frozen() -> HostileFrozenSchedulerMapping:
    HostileFrozenSchedulerMapping.touched = 0
    return object.__new__(HostileFrozenSchedulerMapping)


def test_final_json_exact_mapping_rejects_frozen_subclass_without_items_hook():
    hostile = _hostile_frozen()

    assert exact_mapping_items(hostile) is None

    assert HostileFrozenSchedulerMapping.touched == 0


def test_scheduler_evidence_collection_rejects_frozen_subclass_without_items_hook():
    hostile = _hostile_frozen()

    assert scheduler_evidence_mapping_items(hostile) is None
    records = collect_scheduler_evidence(hostile)

    assert HostileFrozenSchedulerMapping.touched == 0
    assert len(records) == 1
    assert records[0].error_category == "scheduler_evidence_source_rejected"
    assert records[0].fatal is True
    assert records[0].context["unsupported_scheduler_evidence_source"]["value_type"] == "HostileFrozenSchedulerMapping"


def test_replay_result_mapping_rejects_frozen_subclass_without_items_hook():
    hostile = _hostile_frozen()

    assert replay_mapping_items(hostile) is None
    with pytest.raises(RuntimeError, match="malformed scheduler replay result record"):
        replay_mapping_value(hostile, "status")

    assert HostileFrozenSchedulerMapping.touched == 0


def test_hybrid_counts_rejects_frozen_subclass_without_items_hook():
    hostile = _hostile_frozen()

    with pytest.raises(HybridQueueStateError, match="invalid hybrid queue count mapping"):
        validate_hybrid_counts(hostile)

    assert HostileFrozenSchedulerMapping.touched == 0
