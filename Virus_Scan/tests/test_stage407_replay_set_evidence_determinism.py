from Virus_Scan.contracts.result_record import ReplayComparableResultSnapshot


def _record(evidence_items):
    return {
        "path": "sample.bin",
        "filename": "sample.bin",
        "extension": ".bin",
        "verdict": "high",
        "score": 75,
        "tags": ["embedded_payload"],
        "chains": ["payload_chain"],
        "evidence": {"items": evidence_items},
        "errors": [],
        "warnings": [],
    }


def test_replay_snapshot_canonicalizes_unordered_set_evidence():
    left = ReplayComparableResultSnapshot.from_record(_record({"zeta", "alpha", "middle"}))
    right = ReplayComparableResultSnapshot.from_record(_record({"middle", "zeta", "alpha"}))

    assert left == right
    assert left.digest_payload()["evidence"]["items"] == ["alpha", "middle", "zeta"]
