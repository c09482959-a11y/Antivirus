from Virus_Scan.tests.support.static_inventory import read_python_file

import ast
from pathlib import Path

from Virus_Scan.models import profiles
from Virus_Scan.models.profiles import default_extension_baseline
from Virus_Scan.models.profiles.extension_learning import update_behavior_bucket_learning
import Virus_Scan.detection.api.tags_contracts as tags_contracts
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence



def test_profile_learning_bucket_update_is_model_owned_and_resolves_names():
    baseline = default_extension_baseline(".txt")
    result = update_behavior_bucket_learning(
        baseline,
        physical_tag_evidence(("powershell_execution", "credential_access")),
        strings_blob="powershell credential",
        api_calls=["CreateProcessW"],
        ordered_events=["read", "execute"],
    )

    assert result["updated"] is True
    assert "os_execution" in baseline["behavior_buckets"]
    assert "credential" in baseline["behavior_buckets"]
    assert baseline["behavior_buckets"]["os_execution"]["tags"]["powershell_execution"] == 1
    assert baseline["behavior_buckets"]["credential"]["tags"]["credential_access"] == 1
    assert baseline["tag_evidence"]["powershell_execution"]
    assert baseline["tag_evidence"]["credential_access"]


def test_profile_learning_uses_profile_bucket_owner_not_missing_detection_publication_symbols():
    source = read_python_file(Path("Virus_Scan/models/profiles/extension_learning.py"))
    tree = ast.parse(source)
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)
        elif isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)

    assert "Virus_Scan.detection.publication.behavior_learning" not in imports
    call_names = {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert "tag_behavior_bucket" not in call_names
    assert "profile_tag_behavior_bucket" in call_names
    assert "def update_behavior_bucket_learning" in source
    assert "Virus_Scan.models.profiles.api" not in source


def test_profile_public_facade_does_not_publish_direct_learning_mutators():
    assert "update_behavior_bucket_learning" not in profiles.__all__
    assert not hasattr(profiles, "update_behavior_bucket_learning")


def test_detection_tags_contract_does_not_publish_profile_learning_mutators():
    assert not Path("Virus_Scan/detection/publication/behavior_learning.py").exists()
    assert "update_behavior_bucket_learning" not in tags_contracts.__all__
    assert "update_global_tag_stats" not in tags_contracts.__all__
    assert not hasattr(tags_contracts, "update_behavior_bucket_learning")
    assert not hasattr(tags_contracts, "update_global_tag_stats")
