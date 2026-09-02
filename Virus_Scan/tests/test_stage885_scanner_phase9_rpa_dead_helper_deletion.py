from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.scanners import renpy
from Virus_Scan.scanners.archives import rpa_member_behavior
from Virus_Scan.scanners.ci.suppressed_failure_audit import validate_suppressed_failure_manifest



def test_renpy_no_longer_contains_duplicate_private_rpa_member_behavior_helper():
    source = read_python_file(Path("Virus_Scan/scanners/renpy.py"))
    assert "def _rpa_decoded_member_behavior_tags" not in source
    assert "_archive_rpa_decoded_member_behavior_tags" in source
    assert renpy.rpa_decoded_member_behavior_tags is not None


def test_renpy_public_rpa_member_behavior_delegates_to_archive_owned_boundary():
    sample = b"RPA-3.0 not_hex 00000000\nrenpy pickle python exec("
    public_tags = renpy.rpa_decoded_member_behavior_tags(sample, path="bad_scripts.rpa")
    archive_tags = rpa_member_behavior.rpa_decoded_member_behavior_tags(sample, path="bad_scripts.rpa")
    assert public_tags == archive_tags
    lowered = {str(tag).lower() for tag in public_tags}
    assert "scanner_failure_evidence_recorded" in lowered
    assert "scanner_failure_evidence:archive_rpa:rpa_member_parse" in lowered
    assert "archive_final_json_must_record" in lowered


def test_suppressed_failure_manifest_removes_deleted_duplicate_rpa_helper():
    report = validate_suppressed_failure_manifest(Path("."))
    assert report["total_calls"] == 38
    assert report["unclassified"] == []
    assert report["stale_manifest"] == []
    assert report["count_mismatches"] == []
    assert not any(
        item["function"] == "_rpa_decoded_member_behavior_tags"
        and item["module"] == "Virus_Scan/scanners/renpy.py"
        for item in report["manifest"]
    )
