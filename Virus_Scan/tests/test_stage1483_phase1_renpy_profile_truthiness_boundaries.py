from __future__ import annotations

from Virus_Scan.detection.profiles.family_scan import explicit_missed_family_tag_scan
from Virus_Scan.detection.profiles.renpy.updater import (
    apply_renpy_failsafe_only_cap,
    apply_renpy_updater_baseline,
    renpy_updater_has_hard_anchor,
    renpy_updater_score_cap,
    suppress_renpy_bytecode_noise,
)
from Virus_Scan.detection.profiles.renpy.updater_identity import is_renpy_official_updater_path
from Virus_Scan.detection.profiles.renpy.updater_text import (
    has_any_text,
    high_gate_norm,
    is_renpy_bytecode_path,
    sanitize_tag_part,
)


class HostileBoolIterable:
    def __init__(self, values):
        self._values = tuple(values)

    def __bool__(self):  # pragma: no cover - the test fails if reached
        raise AssertionError("profile boundary used caller-owned truthiness")

    def __iter__(self):
        return iter(self._values)


class HostileBoolText:
    def __init__(self, value):
        self._value = value

    def __bool__(self):  # pragma: no cover - the test fails if reached
        raise AssertionError("profile text boundary used caller-owned truthiness")

    def __str__(self):
        return self._value


class HostileBoolBytes:
    def __init__(self, value: bytes):
        self._value = value

    def __bool__(self):  # pragma: no cover - the test fails if reached
        raise AssertionError("profile bytes boundary used caller-owned truthiness")

    def __len__(self):
        return len(self._value)

    def __getitem__(self, item):
        return self._value[item]


OFFICIAL_UPDATER_TEXT = (
    "Tom Rothamel class Updater zsync_path downloadneeded requests tarfile "
    "normal zsync updater archive"
)


def test_stage1483_renpy_updater_text_helpers_do_not_probe_truthiness():
    assert has_any_text(HostileBoolText("PowerShell -Enc"), HostileBoolIterable(["powershell"]))
    assert high_gate_norm(HostileBoolIterable(["RenPy", " binary_failover_scan "])) == {
        "renpy",
        "binary_failover_scan",
    }
    assert sanitize_tag_part(HostileBoolText("PowerShell Exec")) == "powershell_exec"
    assert is_renpy_bytecode_path(HostileBoolText("game/renpy/common/00updater.rpyc"))


def test_stage1483_renpy_updater_identity_does_not_probe_path_truthiness():
    assert is_renpy_official_updater_path(
        HostileBoolText("game/renpy/common/00updater.rpy"),
        OFFICIAL_UPDATER_TEXT,
    )


def test_stage1483_renpy_updater_public_paths_freeze_hostile_tag_inputs():
    hostile_tags = HostileBoolIterable(["renpy", "binary_failover_scan"])

    assert renpy_updater_has_hard_anchor(
        HostileBoolIterable(["renpy_updater_external_process_abuse"]),
        strings_blob="",
        path=HostileBoolText(""),
    )

    capped, evidence = apply_renpy_failsafe_only_cap(42.0, hostile_tags)
    assert capped == 12.0
    assert evidence is not None
    assert evidence["name"] == "renpy_failsafe_only_low_cap"

    score, reasons = renpy_updater_score_cap(
        80.0,
        tags=HostileBoolIterable(["renpy"]),
        path=HostileBoolText("game/renpy/common/00updater.rpy"),
        strings_blob=OFFICIAL_UPDATER_TEXT,
    )
    assert score == 22.0
    assert reasons == ["renpy_official_updater_cap_score"]


def test_stage1483_renpy_updater_baseline_and_bytecode_noise_freeze_hostile_inputs():
    baseline = apply_renpy_updater_baseline(
        HostileBoolIterable(["network_download", "process_exec"]),
        path=HostileBoolText("game/renpy/common/00updater.rpy"),
        strings_blob=OFFICIAL_UPDATER_TEXT,
    )
    assert "renpy_updater_baseline_v1" in baseline
    assert "renpy_update_download_capability" in baseline

    cleaned = suppress_renpy_bytecode_noise(
        HostileBoolIterable(["renpy_bytecode", "network_activity", "actual_stage_binary"]),
        path=HostileBoolText("game/renpy/common/00updater.rpyc"),
        strings_blob="",
    )
    assert "renpy_bytecode_noise_suppressed" in cleaned
    assert "network_activity" not in cleaned


def test_stage1483_family_profile_scan_does_not_probe_public_input_truthiness():
    tags = explicit_missed_family_tag_scan(
        HostileBoolText("steghide hidden payload after iend"),
        path=HostileBoolText("assets/renpy/common/image.png"),
        data=HostileBoolBytes(b"\x89PNG" + b"A" * 2048 + b"MZ"),
        renpy_loader_family_tags_func=lambda *args, **kwargs: (),
    )
    assert "image_payload_candidate" in tags
    assert "possible_stego_payload" in tags
