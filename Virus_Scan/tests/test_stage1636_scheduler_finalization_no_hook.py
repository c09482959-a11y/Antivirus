from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from collections.abc import Mapping
from pathlib import Path

from Virus_Scan.scheduler.orchestration.finalization import (
    SchedulerPipelineFinalizationDependencies,
    SchedulerPipelineFinalizationRequest,
    finalize_scheduler_pipeline,
    scheduler_results_have_learning_candidate,
)


class HostileResults(Mapping):
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("iter hook executed")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("len hook executed")

    def __getitem__(self, key):
        type(self).touched += 1
        raise RuntimeError("getitem hook executed")

    def values(self):
        type(self).touched += 1
        raise RuntimeError("values hook executed")


class HostileRecord(Mapping):
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("record iter hook executed")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("record len hook executed")

    def __getitem__(self, key):
        type(self).touched += 1
        raise RuntimeError("record getitem hook executed")

    def get(self, key, default=None):
        type(self).touched += 1
        raise RuntimeError("record get hook executed")


class HostileSchedulerMode:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("mode bool hook executed")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("mode str hook executed")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("mode repr hook executed")


class HostilePersistException(Exception):
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("exception str hook executed")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("exception repr hook executed")


def test_stage1636_learning_candidate_rejects_hostile_results_without_mapping_hooks():
    HostileResults.touched = 0

    assert scheduler_results_have_learning_candidate(HostileResults()) is False

    assert HostileResults.touched == 0


def test_stage1636_learning_candidate_rejects_hostile_record_without_get_hook():
    HostileRecord.touched = 0

    assert scheduler_results_have_learning_candidate({"sample": HostileRecord()}) is False

    assert HostileRecord.touched == 0


def test_stage1636_finalization_rejects_hostile_mode_and_exception_text_without_hooks():
    calls = []
    HostileSchedulerMode.touched = 0
    HostilePersistException.touched = 0

    def persist(_results):
        raise HostilePersistException("do not stringify")

    finalize_scheduler_pipeline(
        SchedulerPipelineFinalizationRequest(
            results={"sample": {"fast_path": False, "learn_eligible": True}},
            scheduler_mode=HostileSchedulerMode(),
            strict=False,
            process_shard=False,
            freeze_existing_baselines=False,
            profile_policy_snapshot="snapshot",
        ),
        SchedulerPipelineFinalizationDependencies(
            persist_parent_learning_from_results=persist,
            flush_all_persistent_models=lambda **_kwargs: calls.append("flush"),
            restore_profile_policy=lambda snapshot: calls.append(("restore", snapshot)),
            clear_profile_scoring_snapshot=lambda: calls.append("clear"),
            write_partial=lambda **kwargs: calls.append(("write_partial", kwargs.get("force"))),
            log_error=lambda message: calls.append(("error", message)),
            recoverable_exceptions=(HostilePersistException,),
        ),
    )

    assert HostileSchedulerMode.touched == 0
    assert HostilePersistException.touched == 0
    assert ("restore", "snapshot") in calls
    assert ("write_partial", True) in calls
    assert any(
        call[0] == "error"
        and "parent learning replay failed at pipeline end: HostilePersistException" in call[1]
        for call in calls
        if type(call) is tuple
    )


def test_stage1636_scheduler_finalization_source_has_no_hookable_result_fallbacks():
    source = read_python_file(Path("Virus_Scan/scheduler/orchestration/finalization.py"))

    assert "results or {}" not in source
    assert "(results or {})" not in source
    assert ".values()" not in source
    assert ".get(\"fast_path\")" not in source
    assert ".get(\"learn_eligible" not in source
    assert "str(request.scheduler_mode" not in source
    assert "f\"parent learning replay failed" not in source
    assert "f\"persistent model flush failed" not in source
