from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.models.contracts.model_failure import (
    make_model_failure_record,
    materialize_model_failure_record,
)


class HostilePrivateDataMapping(Mapping):
    touched = 0

    @property
    def _data(self):  # pragma: no cover - failure proves private descriptor probing returned
        type(self).touched += 1
        raise AssertionError("private _data descriptor touched")

    def __iter__(self):  # pragma: no cover - failure proves caller-owned iteration returned
        type(self).touched += 1
        raise AssertionError("mapping iteration touched")

    def __len__(self):  # pragma: no cover - failure proves caller-owned len/truthiness returned
        type(self).touched += 1
        raise AssertionError("mapping len touched")

    def __getitem__(self, key):  # pragma: no cover - failure proves caller-owned lookup returned
        type(self).touched += 1
        raise AssertionError("mapping getitem touched")


def test_stage1643_model_failure_details_reject_hostile_private_data_mapping_without_hooks() -> None:
    HostilePrivateDataMapping.touched = 0

    record = make_model_failure_record(
        model_name="profiles",
        failure_type="profile_failure",
        reason="profile_unavailable",
        details=HostilePrivateDataMapping(),
    )

    assert record["details"]["unavailable_reason"] == "unreadable_model_failure_mapping"
    assert record["details"]["value_type"] == "HostilePrivateDataMapping"
    assert HostilePrivateDataMapping.touched == 0


def test_stage1643_model_failure_materialization_rejects_hostile_private_data_mapping_without_hooks() -> None:
    HostilePrivateDataMapping.touched = 0

    materialized = materialize_model_failure_record(HostilePrivateDataMapping())

    assert materialized["unavailable_reason"] == "unreadable_model_failure_mapping"
    assert materialized["value_type"] == "HostilePrivateDataMapping"
    assert HostilePrivateDataMapping.touched == 0
