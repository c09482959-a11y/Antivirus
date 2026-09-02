from Virus_Scan.scheduler.queue.admission import build_workload_classification_plan, classify_workload, workload_plan_summary


class HostileAdmissionValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    fspath_calls = 0

    @classmethod
    def reset(cls):
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.bool_calls = 0
        cls.iter_calls = 0
        cls.fspath_calls = 0

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("must not execute __str__")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("must not execute __repr__")

    def __format__(self, spec):
        type(self).format_calls += 1
        raise RuntimeError("must not execute __format__")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("must not execute __bool__")

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("must not execute __iter__")

    def __fspath__(self):
        type(self).fspath_calls += 1
        raise RuntimeError("must not execute __fspath__")


def _assert_no_hostile_hooks():
    assert HostileAdmissionValue.str_calls == 0
    assert HostileAdmissionValue.repr_calls == 0
    assert HostileAdmissionValue.format_calls == 0
    assert HostileAdmissionValue.bool_calls == 0
    assert HostileAdmissionValue.iter_calls == 0
    assert HostileAdmissionValue.fspath_calls == 0


def test_stage1779_classify_workload_rejects_hostile_stage_tags_and_path_before_hooks():
    HostileAdmissionValue.reset()
    hostile = HostileAdmissionValue()

    assert classify_workload(hostile, stage=hostile, tags=[hostile]) == "generic"

    _assert_no_hostile_hooks()


def test_stage1779_workload_plan_summary_rejects_hostile_paths_without_empty_default_or_hooks():
    HostileAdmissionValue.reset()
    hostile = HostileAdmissionValue()

    summary = workload_plan_summary(build_workload_classification_plan(["archives/game.rpa", hostile, "media/title.png"]))

    _assert_no_hostile_hooks()
    assert summary["counts"]["archive"] == 1
    assert summary["counts"]["image"] == 1
    assert summary["counts"]["generic"] == 1
    assert summary["path_rejections"] == 1
    assert summary["separated"] == 1


def test_stage1779_classify_workload_preserves_exact_stage_tag_and_extension_behavior():
    assert classify_workload(stage="yara rule scan") == "yara"
    assert classify_workload(stage="extract archive") == "archive"
    assert classify_workload(tags=("dotnet", "ilspy")) == "dotnet"
    assert classify_workload("sprites/title.png") == "image"
    assert classify_workload("scripts/bootstrap.rpy") == "script"
