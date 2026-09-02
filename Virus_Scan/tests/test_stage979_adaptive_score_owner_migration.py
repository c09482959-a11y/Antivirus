from pathlib import Path

from Virus_Scan.reporting.risk_label import risk_label_from_score


def test_adaptive_score_authority_migrated_to_detection_scoring():
    assert not Path("Virus_Scan/models/scoring.py").exists()
    assert not Path("Virus_Scan/models/scoring_state.py").exists()
    assert Path("Virus_Scan/detection/scoring/adaptive/model_score.py").exists()
    assert Path("Virus_Scan/detection/scoring/adaptive/calibration_state.py").exists()


def test_profile_scoring_state_runtime_snapshot_owned_not_model_owned():
    assert Path("Virus_Scan/runtime/profile_scoring_state.py").exists()
    assert not Path("Virus_Scan/detection/scoring/profile_state.py").exists()
    assert not Path("Virus_Scan/models/profile_state.py").exists()


def test_reporting_risk_label_is_display_only():
    assert risk_label_from_score(0) == "LOW"
    assert risk_label_from_score(25) == "MEDIUM"
    assert risk_label_from_score(50) == "HIGH"
    assert risk_label_from_score(75) == "MALICIOUS"
