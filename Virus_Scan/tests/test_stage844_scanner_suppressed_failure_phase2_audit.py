from Virus_Scan.scanners.ci.suppressed_failure_audit import validate_suppressed_failure_manifest


def test_scanner_suppressed_failure_phase2_inventory_is_complete():
    report = validate_suppressed_failure_manifest('.')

    assert report['total_calls'] == 38
    assert report['unclassified'] == []
    assert report['stale_manifest'] == []
    assert report['count_mismatches'] == []
    assert report['unsafe_classifications'] == []
