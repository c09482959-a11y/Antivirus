from __future__ import annotations

from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_mapping_items
from Virus_Scan.scheduler.internal.immutable_outputs import FrozenSchedulerMapping, immutable_value, materialize_scheduler_mapping
from Virus_Scan.scheduler.orchestration.process_queue_completion_evidence import collect_nonclean_worker_exit_evidence


class HostileFrozenSchedulerMapping(FrozenSchedulerMapping):
    touched = 0

    @property
    def _items(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("do not call hostile _items")


def _hostile_frozen() -> HostileFrozenSchedulerMapping:
    HostileFrozenSchedulerMapping.touched = 0
    return object.__new__(HostileFrozenSchedulerMapping)


def test_materialize_scheduler_mapping_rejects_frozen_subclass_without_items_hook():
    hostile = _hostile_frozen()

    result = materialize_scheduler_mapping(hostile)

    assert HostileFrozenSchedulerMapping.touched == 0
    assert result["unsupported_scheduler_value"] is True
    assert result["value_type"] == "HostileFrozenSchedulerMapping"
    assert result["final_json_must_record"] is True
    assert result["replay_must_record"] is True


def test_immutable_value_rejects_frozen_subclass_without_preserving_hostile_mapping():
    hostile = _hostile_frozen()

    result = immutable_value(hostile)

    assert HostileFrozenSchedulerMapping.touched == 0
    assert result["unsupported_scheduler_value"] is True
    assert result["value_type"] == "HostileFrozenSchedulerMapping"


def test_scheduler_mapping_items_rejects_frozen_subclass_without_items_hook():
    hostile = _hostile_frozen()

    assert scheduler_mapping_items(hostile) is None
    assert HostileFrozenSchedulerMapping.touched == 0


def test_process_queue_completion_evidence_rejects_frozen_subclass_without_items_hook():
    hostile = _hostile_frozen()

    result = collect_nonclean_worker_exit_evidence((hostile,))

    assert HostileFrozenSchedulerMapping.touched == 0
    assert len(result) == 1
    assert result[0]["process_queue_worker_exit_evidence_unavailable"] is True
    assert result[0]["value_type"] == "HostileFrozenSchedulerMapping"
