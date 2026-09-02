from Virus_Scan.scheduler.orchestration.finalization import (
    SchedulerPipelineFinalizationDependencies,
    SchedulerPipelineFinalizationRequest,
    finalize_scheduler_pipeline,
    scheduler_results_have_learning_candidate,
)


def test_stage701_learning_candidate_detection_is_scheduler_owned():
    assert scheduler_results_have_learning_candidate({"a": {"fast_path": False, "learn_eligible": True}})
    assert not scheduler_results_have_learning_candidate({"a": {"fast_path": True, "learn_eligible": True}})
    assert not scheduler_results_have_learning_candidate({"a": {"fast_path": False, "learn_eligible": False}})


def test_stage701_parent_finalization_owns_learning_flush_and_profile_restore():
    calls = []

    def persist(results):
        calls.append(("persist", tuple(results)))

    def flush_all(*, force=False):
        calls.append(("flush", force))

    def restore(snapshot):
        calls.append(("restore", snapshot))

    def clear_snapshot():
        calls.append(("clear", None))

    def write_partial(*, force=False):
        calls.append(("write_partial", force))

    finalize_scheduler_pipeline(
        SchedulerPipelineFinalizationRequest(
            results={"sample": {"fast_path": False, "learn_eligible": True}},
            scheduler_mode="process",
            strict=True,
            process_shard=False,
            freeze_existing_baselines=True,
            profile_policy_snapshot={"old": True},
        ),
        SchedulerPipelineFinalizationDependencies(
            persist_parent_learning_from_results=persist,
            flush_all_persistent_models=flush_all,
            restore_profile_policy=restore,
            clear_profile_scoring_snapshot=clear_snapshot,
            write_partial=write_partial,
            log_error=lambda message: calls.append(("error", message)),
            recoverable_exceptions=(Exception,),
        ),
    )

    assert calls == [
        ("persist", ("sample",)),
        ("flush", True),
        ("restore", {"old": True}),
        ("clear", None),
        ("write_partial", True),
    ]


def test_stage701_process_shard_skips_parent_learning_but_restores_state():
    calls = []
    finalize_scheduler_pipeline(
        SchedulerPipelineFinalizationRequest(
            results={"sample": {"fast_path": False, "learn_eligible": True}},
            scheduler_mode="process",
            strict=True,
            process_shard=True,
            freeze_existing_baselines=False,
            profile_policy_snapshot="snapshot",
        ),
        SchedulerPipelineFinalizationDependencies(
            persist_parent_learning_from_results=lambda results: calls.append("persist"),
            flush_all_persistent_models=lambda **kwargs: calls.append("flush"),
            restore_profile_policy=lambda snapshot: calls.append(("restore", snapshot)),
            clear_profile_scoring_snapshot=lambda: calls.append("clear"),
            write_partial=lambda **kwargs: calls.append(("write_partial", kwargs.get("force"))),
            log_error=lambda message: calls.append(("error", message)),
            recoverable_exceptions=(Exception,),
        ),
    )
    assert calls == [("restore", "snapshot"), ("write_partial", True)]
