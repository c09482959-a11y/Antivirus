from __future__ import annotations

from typing import Any, cast

import pytest

from Virus_Scan.scheduler.context.dependency_snapshot import SchedulerDependencySnapshot


def test_phase9_dependency_snapshot_preserves_binding_names_through_json_boundary() -> None:
    mutable_metadata = {"evidence": {"missing": ["none"]}}
    snapshot = SchedulerDependencySnapshot(
        bindings={"scan_file": object(), "emit_result": object()},
        public_contracts=("scheduler.api.runner",),
        evidence=(mutable_metadata,),
    )

    encoded = snapshot.as_dict()
    decoded = SchedulerDependencySnapshot.from_mapping(encoded)

    mutable_metadata["evidence"]["missing"].append("caller-mutation")

    assert encoded["binding_names"] == ["emit_result", "scan_file"]
    assert decoded.binding_names == ("emit_result", "scan_file")
    assert decoded.as_dict()["binding_names"] == ["emit_result", "scan_file"]
    assert decoded.evidence[0]["evidence"]["missing"] == ("none",)


def test_phase9_dependency_snapshot_accepts_serialized_binding_names_without_callable_fallbacks() -> None:
    snapshot = SchedulerDependencySnapshot.from_mapping(
        {
            "binding_names": ["public_scan_contract", "result_writer_contract"],
            "public_contracts": ["scheduler.api.runner"],
            "missing_dependencies": ["optional_report_sink"],
        }
    )

    assert tuple(snapshot.bindings.keys()) == ()
    assert snapshot.binding_names == ("public_scan_contract", "result_writer_contract")
    assert snapshot.public_contracts == ("scheduler.api.runner",)
    assert snapshot.missing_dependencies == ("optional_report_sink",)


def test_phase9_dependency_snapshot_binding_names_are_immutable() -> None:
    names = ["scan_file"]
    snapshot = cast(Any, SchedulerDependencySnapshot)(binding_names=names)
    names.append("mutated")

    assert snapshot.binding_names == ("scan_file",)
    with pytest.raises(AttributeError):
        snapshot.binding_names = ("changed",)  # type: ignore[misc]
