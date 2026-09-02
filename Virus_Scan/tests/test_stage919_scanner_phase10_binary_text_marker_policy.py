"""Stage 919 Phase 10 binary text marker policy tests."""
from __future__ import annotations

from Virus_Scan.scanners.binary_text_signals import binary_text_has_any


def test_binary_text_marker_empty_needles_do_not_fail_open() -> None:
    assert binary_text_has_any("benign text", ["", None, "   "]) is False


def test_binary_text_marker_valid_needles_still_match() -> None:
    assert binary_text_has_any("prefix powershell suffix", ["cmd.exe", "powershell"]) is True


def test_binary_text_marker_missing_valid_needles_stays_false() -> None:
    assert binary_text_has_any("benign text", ["cmd.exe", "powershell"]) is False
