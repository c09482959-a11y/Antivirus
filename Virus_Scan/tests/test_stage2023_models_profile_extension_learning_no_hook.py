from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.models.profiles.extension_learning import update_behavior_bucket_learning
from Virus_Scan.models.profiles.snapshots import default_extension_baseline
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


def test_stage2023_behavior_bucket_learning_uses_explicit_update_count() -> None:
    baseline = default_extension_baseline(".rpy")

    result = update_behavior_bucket_learning(
        baseline, physical_tag_evidence(("browser_xhr_fetch",), one_root=True),
    )

    assert result["updated"] is True
    assert result["tags"]
    assert baseline["behavior_buckets"]["other"]["tags"]["browser_xhr_fetch"] == 1


def test_stage2023_behavior_bucket_learning_source_has_no_bool_or_row_items_probe() -> None:
    source = read_python_file(Path("Virus_Scan/models/profiles/extension_learning.py"))

    assert "bool(updated_tags)" not in source
    assert "row.items()" not in source
    assert "len(updated_tags) > 0" in source
    assert "dict.items(row)" in source
