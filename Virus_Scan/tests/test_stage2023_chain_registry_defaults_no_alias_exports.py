from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.detection.registries.chain_registry import chain_rule
from Virus_Scan.detection.registries.snapshot import build_detection_registry_snapshot
from Virus_Scan.detection.tags.heuristics.vocabulary import canonical_tag_name



def test_stage2023_chain_registry_defaults_removed_dead_alias_exports() -> None:
    source = read_python_file(Path("Virus_Scan/detection/registries/chain_registry_defaults.py"))
    snapshot = build_detection_registry_snapshot()
    values = snapshot.chain_registry.values

    assert "CANONICAL_TAG_ALIASES =" not in source
    assert "CANONICAL_CHAIN_ALIASES_V3 =" not in source
    assert "CANONICAL_TAG_ALIASES" not in values
    assert "CANONICAL_CHAIN_ALIASES_V3" not in values
    assert values["CHAIN_REGISTRY_VERSION"] == "stage2636_11020_chain_registry_v5"
    assert "CHAIN_ROLE_EXPECTED_BEHAVIOR" in values


def test_stage2023_chain_and_tag_canonicalization_stay_with_canonical_owners() -> None:
    assert canonical_tag_name("powershell_encoded") == "encoded_powershell"
    assert chain_rule("network_download_execute") is None
    assert not Path("Virus_Scan/detection/chains/composite/policy.py").exists()
