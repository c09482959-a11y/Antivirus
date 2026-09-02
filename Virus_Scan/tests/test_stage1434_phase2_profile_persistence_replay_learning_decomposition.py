from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.models import profiles



def test_profile_persistence_and_replay_learning_have_explicit_owners():
    assert profiles.load_engine_profile.__module__ == "Virus_Scan.models.profiles.persistence"
    assert profiles.save_engine_profile.__module__ == "Virus_Scan.models.profiles.persistence"
    assert profiles.flush_profile_writes.__module__ == "Virus_Scan.models.profiles.persistence"
    assert profiles.get_benign_candidate_store.__module__ == "Virus_Scan.models.profiles.replay_learning"
    assert profiles.save_benign_candidate_store.__module__ == "Virus_Scan.models.profiles.replay_learning"
    assert profiles.flush_benign_candidate_store.__module__ == "Virus_Scan.models.profiles.replay_learning"


def test_profile_persistence_and_replay_learning_do_not_import_api_owner():
    persistence_source = read_python_file(Path("Virus_Scan/models/profiles/persistence.py"))
    replay_learning_source = read_python_file(Path("Virus_Scan/models/profiles/replay_learning.py"))
    assert "from Virus_Scan.models.profiles.api" not in persistence_source
    assert "import Virus_Scan.models.profiles.api" not in persistence_source
    assert "from Virus_Scan.models.profiles.api" not in replay_learning_source
    assert "import Virus_Scan.models.profiles.api" not in replay_learning_source


def test_profile_persistence_split_reduces_api_and_bounds_owner_modules():
    api_lines = read_python_file(Path("Virus_Scan/models/profiles/api.py")).splitlines()
    persistence_lines = read_python_file(Path("Virus_Scan/models/profiles/persistence.py")).splitlines()
    replay_learning_lines = read_python_file(Path("Virus_Scan/models/profiles/replay_learning.py")).splitlines()
    assert len(api_lines) < 1400
    assert len(persistence_lines) < 250
    assert len(replay_learning_lines) < 200


def test_profile_replay_learning_store_exports_preserve_public_profile_imports(tmp_path):
    store = {"schema_version": profiles.PROFILE_SCHEMA_VERSION, "candidates": {}, "promotions": 0, "rejections": {}}
    assert profiles.mark_benign_candidate_store_dirty(store) in {True, None}
    cached = profiles.get_benign_candidate_store()
    assert isinstance(cached, dict)
