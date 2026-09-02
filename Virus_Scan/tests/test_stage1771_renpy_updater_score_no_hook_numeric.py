from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.detection.profiles.renpy.updater import (
    apply_renpy_failsafe_only_cap,
    renpy_updater_score_cap,
)


OFFICIAL_UPDATER_TEXT = (
    "Tom Rothamel class Updater zsync_path downloadneeded requests tarfile "
    "normal zsync updater archive"
)


class HostileScore:
    float_calls = 0
    int_calls = 0
    str_calls = 0
    repr_calls = 0

    def __float__(self):
        type(self).float_calls += 1
        raise RuntimeError("hostile __float__ must not execute")

    def __int__(self):
        type(self).int_calls += 1
        raise RuntimeError("hostile __int__ must not execute")

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("hostile __str__ must not execute")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("hostile __repr__ must not execute")


def _reset_hostile_score():
    HostileScore.float_calls = 0
    HostileScore.int_calls = 0
    HostileScore.str_calls = 0
    HostileScore.repr_calls = 0


def _assert_no_hostile_score_hooks():
    assert HostileScore.float_calls == 0
    assert HostileScore.int_calls == 0
    assert HostileScore.str_calls == 0
    assert HostileScore.repr_calls == 0


def test_renpy_updater_score_cap_rejects_hostile_score_without_numeric_hooks():
    _reset_hostile_score()

    score, reasons = renpy_updater_score_cap(
        HostileScore(),
        tags=("renpy",),
        path="game/renpy/common/00updater.rpy",
        strings_blob=OFFICIAL_UPDATER_TEXT,
    )

    assert score == 0.0
    assert reasons == [
        "renpy_updater_score_unavailable",
        "renpy_official_updater_cap_score",
    ]
    _assert_no_hostile_score_hooks()


def test_renpy_failsafe_cap_rejects_hostile_score_with_explicit_evidence():
    _reset_hostile_score()

    score, evidence = apply_renpy_failsafe_only_cap(
        HostileScore(),
        tags=("renpy", "binary_failover_scan"),
    )

    assert score == 0.0
    assert evidence == {
        "name": "renpy_failsafe_score_unavailable",
        "reason": "renpy_failsafe_score_unavailable",
        "old_score": 0.0,
        "new_score": 0.0,
        "confidence_degraded": True,
        "json_record_required": True,
        "replay_record_required": True,
    }
    _assert_no_hostile_score_hooks()


def test_renpy_updater_numeric_source_uses_no_hook_score_materialization():
    source = read_python_file(Path("Virus_Scan/detection/profiles/renpy/updater.py"))
    assert "float(0.0 if score is None else score)" not in source
    assert "except RECOVERABLE_RUNTIME_ERRORS" not in source
    assert "no_hook_finite_float" in source
