from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.detection.tags.evidence_generation import finalize_tag_evidence_generation
from Virus_Scan.utils.reference_url_policy import suppress_reference_url_false_positives



def test_stage383_reference_url_policy_has_single_canonical_implementation():
    scanner_source = read_python_file(Path("Virus_Scan/scanners/text.py"))
    renpy_profile_source = read_python_file(Path("Virus_Scan/detection/profiles/renpy/updater.py"))
    assert "def suppress_reference_url_false_positives" not in scanner_source
    assert "def suppress_reference_url_false_positives" not in renpy_profile_source
    assert "from Virus_Scan.utils.reference_url_policy import suppress_reference_url_false_positives" in renpy_profile_source


def test_stage383_reference_url_policy_preserves_source_url_suppression():
    tags = ["network_activity", "defense_evasion", "benign_context"]
    text = "# See https://example.invalid/docs for mod instructions"
    cleaned = suppress_reference_url_false_positives(tags, path="script.rpy", strings_blob=text)
    assert "network_activity" not in cleaned
    assert "defense_evasion" not in cleaned
    assert "url_present" in cleaned
    assert "reference_url" in cleaned
    assert "reference_url_behavior_suppressed" in cleaned


def test_stage383_tag_evidence_generation_uses_canonical_reference_url_policy():
    cleaned = finalize_tag_evidence_generation(
        ["network_activity", "defense_evasion"],
        path="notes.py",
        strings_blob="# docs: https://example.invalid/readme",
    ).evidence.tags
    assert "network_activity" not in cleaned
    assert "defense_evasion" not in cleaned
    assert "reference_url" in cleaned
