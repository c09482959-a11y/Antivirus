from __future__ import annotations

from Virus_Scan.contracts.library_baseline import library_baseline_hard_proof_status
from Virus_Scan.core.paths import runtime_library_score_cap
from Virus_Scan.utils.text_match import has_any_text


class HostileText:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call bool")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not call str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not call repr")

    def __format__(self, spec):
        type(self).touched += 1
        raise RuntimeError("do not call format")


class HostileNeedles:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call bool")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")


class HostileNeedle:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify needle")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr needle")



def test_stage1686_text_match_rejects_hostile_haystack_without_hooks():
    HostileText.touched = 0

    assert has_any_text(HostileText(), ("powershell",)) is False

    assert HostileText.touched == 0



def test_stage1686_text_match_rejects_hostile_needle_container_without_hooks():
    HostileNeedles.touched = 0

    assert has_any_text("powershell -enc", HostileNeedles()) is False

    assert HostileNeedles.touched == 0



def test_stage1686_text_match_rejects_hostile_needle_member_without_hooks():
    HostileNeedle.touched = 0

    assert has_any_text("powershell -enc", (HostileNeedle(),)) is False
    assert has_any_text("powershell -enc", ("powershell",)) is True

    assert HostileNeedle.touched == 0



def test_stage1686_library_and_runtime_callers_preserve_no_hook_text_boundary():
    HostileText.touched = 0

    status, has_proof = library_baseline_hard_proof_status(strings_blob=HostileText())
    capped_score, reasons = runtime_library_score_cap(
        88.0,
        tags=(),
        path="python.dll",
        strings_blob=HostileText(),
        api_calls=(),
        
    )

    assert (status, has_proof) == ("no_hard_proof", False)
    assert capped_score == 22.0
    assert reasons == ["runtime_library_cap_score"]
    assert HostileText.touched == 0
