from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.detection.profiles.renpy.updater import (
    apply_renpy_updater_baseline,
    renpy_updater_has_hard_anchor,
    suppress_renpy_bytecode_noise,
)
from Virus_Scan.detection.profiles.renpy.updater_text import (
    has_any_text,
    high_gate_norm,
    is_renpy_bytecode_path,
    profile_iterable_has_items,
    profile_text_or_empty,
    profile_tuple_or_empty,
    sanitize_tag_part,
)
from Virus_Scan.utils.tagging import DETECTION_STAGE_DEGRADED_TAG, TAG_NORMALIZATION_FAILURE_EVIDENCE


OFFICIAL_UPDATER_TEXT = (
    "Tom Rothamel class Updater zsync_path downloadneeded requests tarfile "
    "normal zsync updater archive"
)


class HostileProfileText:
    str_calls = 0
    repr_calls = 0

    def __init__(self, value="RenPy Update"):
        self._value = value

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("hostile __str__ must not execute")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("hostile __repr__ must not execute")


class UnsupportedHostileText:
    str_calls = 0
    repr_calls = 0

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("hostile unsupported __str__ must not execute")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("hostile unsupported __repr__ must not execute")


class HostileProfileSequence:
    iter_calls = 0
    bool_calls = 0

    def __init__(self, values):
        self._values = tuple(values)

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("hostile __iter__ must not execute")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("hostile __bool__ must not execute")


class UnsupportedHostileIterable:
    iter_calls = 0
    bool_calls = 0

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("unsupported hostile __iter__ must not execute")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("unsupported hostile __bool__ must not execute")


def _reset_hostile_counters():
    HostileProfileText.str_calls = 0
    HostileProfileText.repr_calls = 0
    UnsupportedHostileText.str_calls = 0
    UnsupportedHostileText.repr_calls = 0
    HostileProfileSequence.iter_calls = 0
    HostileProfileSequence.bool_calls = 0
    UnsupportedHostileIterable.iter_calls = 0
    UnsupportedHostileIterable.bool_calls = 0


def _assert_no_hostile_hooks():
    assert HostileProfileText.str_calls == 0
    assert HostileProfileText.repr_calls == 0
    assert UnsupportedHostileText.str_calls == 0
    assert UnsupportedHostileText.repr_calls == 0
    assert HostileProfileSequence.iter_calls == 0
    assert HostileProfileSequence.bool_calls == 0
    assert UnsupportedHostileIterable.iter_calls == 0
    assert UnsupportedHostileIterable.bool_calls == 0


def test_renpy_profile_text_helpers_do_not_call_hostile_string_hooks():
    _reset_hostile_counters()

    assert profile_text_or_empty(HostileProfileText("PowerShell Exec")) == "PowerShell Exec"
    assert profile_text_or_empty(UnsupportedHostileText()) == ""
    assert has_any_text(HostileProfileText("PowerShell -Enc"), ("powershell",))
    assert sanitize_tag_part(HostileProfileText("PowerShell Exec")) == "powershell_exec"
    assert sanitize_tag_part(UnsupportedHostileText()) == "unknown"
    assert is_renpy_bytecode_path(HostileProfileText("game/renpy/common/00updater.rpyc"))

    _assert_no_hostile_hooks()


def test_renpy_profile_sequences_do_not_call_hostile_iter_or_bool_hooks():
    _reset_hostile_counters()

    seq = HostileProfileSequence(("RenPy", " binary_failover_scan "))
    assert profile_tuple_or_empty(seq) == ("RenPy", " binary_failover_scan ")
    assert profile_iterable_has_items(seq)
    assert high_gate_norm(seq) == {"renpy", "binary_failover_scan"}

    unsupported_norm = high_gate_norm(UnsupportedHostileIterable())
    assert unsupported_norm == {TAG_NORMALIZATION_FAILURE_EVIDENCE, DETECTION_STAGE_DEGRADED_TAG}
    assert not profile_iterable_has_items(UnsupportedHostileIterable())

    _assert_no_hostile_hooks()


def test_renpy_updater_public_paths_avoid_raw_tag_stringification_and_iteration():
    _reset_hostile_counters()

    hostile_tags = HostileProfileSequence((
        HostileProfileText("network_download"),
        HostileProfileText("process_exec"),
    ))
    baseline = apply_renpy_updater_baseline(
        hostile_tags,
        path=HostileProfileText("game/renpy/common/00updater.rpy"),
        strings_blob=OFFICIAL_UPDATER_TEXT,
    )
    assert "renpy_updater_baseline_v1" in baseline
    assert "renpy_update_download_capability" in baseline

    assert renpy_updater_has_hard_anchor(
        HostileProfileSequence((HostileProfileText("renpy_updater_external_process_abuse"),)),
        strings_blob="",
        path=HostileProfileText(""),
    )

    cleaned = suppress_renpy_bytecode_noise(
        HostileProfileSequence((
            HostileProfileText("renpy_bytecode"),
            HostileProfileText("network_activity"),
            HostileProfileText("actual_stage_binary"),
        )),
        path=HostileProfileText("game/renpy/common/00updater.rpyc"),
        strings_blob="",
    )
    assert "renpy_bytecode_noise_suppressed" in cleaned
    assert "network_activity" not in cleaned

    _assert_no_hostile_hooks()


def test_renpy_updater_text_source_uses_no_hook_materialization():
    text_source = read_python_file(Path("Virus_Scan/detection/profiles/renpy/updater_text.py"))
    updater_source = read_python_file(Path("Virus_Scan/detection/profiles/renpy/updater.py"))
    assert "str(value)" not in text_source
    assert "tuple(values)" not in text_source
    assert "iter(values)" not in text_source
    assert "str(t).lower()" not in updater_source
    assert "str(tag).lower()" not in updater_source
    assert "no_hook_text" in text_source
    assert "no_hook_sequence_items" in text_source
