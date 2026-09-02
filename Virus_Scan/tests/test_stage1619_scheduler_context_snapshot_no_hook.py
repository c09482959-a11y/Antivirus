from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path
from typing import Any, cast

from Virus_Scan.scheduler.context.config_snapshot import SchedulerConfigSnapshot
from Virus_Scan.scheduler.context.dependency_snapshot import SchedulerDependencySnapshot
from Virus_Scan.scheduler.context.runtime_snapshot import SchedulerRuntimeSnapshot
from Virus_Scan.scheduler.context.writable_paths import SchedulerWritablePaths


class HostileText:
    touched = 0

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("str hook touched")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("repr hook touched")


class HostileInt:
    touched = 0

    def __int__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("int hook touched")

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("bool hook touched")


class HostileFloat:
    touched = 0

    def __float__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("float hook touched")

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("bool hook touched")


class HostileMappingLike:
    touched = 0

    def get(self, key, default=None):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("mapping get touched")

    def __iter__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("iter touched")

    def __len__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("len touched")


class HostileBindingName:
    touched = 0

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("binding name str touched")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("binding name repr touched")


def test_stage1619_scheduler_config_snapshot_rejects_hostile_scalars_without_hooks() -> None:
    HostileText.touched = 0
    HostileInt.touched = 0
    HostileFloat.touched = 0

    snapshot = cast(Any, SchedulerConfigSnapshot)(
        scheduler=HostileText(),
        max_workers=HostileInt(),
        per_file_timeout_sec=HostileFloat(),
        progress_every=HostileInt(),
    )

    assert HostileText.touched == 0
    assert HostileInt.touched == 0
    assert HostileFloat.touched == 0
    assert snapshot.scheduler == "process"
    assert snapshot.max_workers == 0
    assert snapshot.per_file_timeout_sec == 0.0
    assert snapshot.progress_every == 1
    reasons = {record["reason"] for record in snapshot.as_dict()["evidence"]}
    assert "unsupported_scheduler_context_text" in reasons
    assert "unsupported_scheduler_context_int" in reasons
    assert "unsupported_scheduler_context_float" in reasons


def test_stage1619_runtime_and_writable_snapshots_reject_hostile_paths_without_hooks() -> None:
    HostileText.touched = 0
    HostileInt.touched = 0

    runtime = cast(Any, SchedulerRuntimeSnapshot)(
        root=HostileText(),
        runtime_dir=HostileText(),
        queue_dir=HostileText(),
        frozen=HostileInt(),
        onefile=HostileInt(),
    )
    writable = cast(Any, SchedulerWritablePaths)(
        runtime_dir=HostileText(),
        queue_dir=HostileText(),
        checkpoint_dir=HostileText(),
        evidence_dir=HostileText(),
        temp_dir=HostileText(),
    )

    assert HostileText.touched == 0
    assert HostileInt.touched == 0
    assert runtime.root == ""
    assert runtime.frozen is False
    assert writable.queue_dir == ""
    runtime_reasons = {record["reason"] for record in runtime.as_dict()["evidence"]}
    writable_reasons = {record["reason"] for record in writable.as_dict()["evidence"]}
    assert "unsupported_scheduler_context_text" in runtime_reasons
    assert "unsupported_scheduler_context_bool" in runtime_reasons
    assert "unsupported_scheduler_context_text" in writable_reasons


def test_stage1619_dependency_snapshot_rejects_hostile_names_without_str_or_iterating_unknown_mappings() -> None:
    HostileBindingName.touched = 0
    HostileMappingLike.touched = 0

    snapshot = cast(Any, SchedulerDependencySnapshot)(
        binding_names=("scan_file", HostileBindingName()),
        public_contracts=(HostileBindingName(),),
        missing_dependencies=(HostileBindingName(),),
    )
    decoded = SchedulerDependencySnapshot.from_mapping(HostileMappingLike())

    assert HostileBindingName.touched == 0
    assert HostileMappingLike.touched == 0
    assert snapshot.binding_names == ("scan_file",)
    assert decoded.binding_names == ()
    reasons = {record["reason"] for record in snapshot.as_dict()["evidence"]}
    assert "unsupported_scheduler_context_text" in reasons


def test_stage1825_dependency_snapshot_uses_frozen_binding_items_without_mapping_keys_protocol() -> None:
    HostileBindingName.touched = 0

    snapshot = cast(Any, SchedulerDependencySnapshot)(bindings={HostileBindingName(): "callable_ref"})

    assert HostileBindingName.touched == 0
    assert snapshot.binding_names == ("unsupported_scheduler_key_0",)


def test_stage1825_dependency_snapshot_source_does_not_call_mapping_keys() -> None:
    source = read_python_file(Path("Virus_Scan/scheduler/context/dependency_snapshot.py"))

    assert ".keys()" not in source
