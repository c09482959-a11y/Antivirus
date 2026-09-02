import ast
from pathlib import Path

from Virus_Scan.scheduler.replay import replay_projection, replay_validator
from Virus_Scan.scheduler.replay.replay_projection import (
    canonical_replay_sequence,
    queue_replay_result_file_identity,
)
from Virus_Scan.scheduler.replay.replay_validator import (
    assert_scheduler_replay_equivalent,
    normalize_scheduler_replay_results,
)


def test_stage1460_replay_projection_exports_public_owner_names_only():
    exported = tuple(replay_projection.__all__)
    assert exported
    assert not any(name.startswith("_") for name in exported)
    assert "canonical_replay_sequence" in exported
    assert "queue_replay_result_file_identity" in exported
    assert "_canonical_replay_sequence" not in vars(replay_projection)
    assert "_replay_result_file_identity" not in vars(replay_projection)
    assert canonical_replay_sequence(["b", "a", "b", ""]) == ("a", "b")
    assert queue_replay_result_file_identity({"file": "sample.bin"})


def test_stage1460_replay_validator_exports_public_contract_names_only():
    exported = tuple(replay_validator.__all__)
    assert exported
    assert not any(name.startswith("_") for name in exported)
    assert "normalize_scheduler_replay_results" in exported
    assert "assert_scheduler_replay_equivalent" in exported
    assert "_normalize_scheduler_replay_results" not in vars(replay_validator)
    assert "_assert_scheduler_replay_equivalent" not in vars(replay_validator)
    first = [{"job_id": "job-a", "file": "a.bin", "verdict": "clean"}]
    second = [{"job_id": "job-a", "file": "a.bin", "verdict": "clean"}]
    assert normalize_scheduler_replay_results(first).job_count == 1
    assert assert_scheduler_replay_equivalent(first, second).job_count == 1


def test_stage1460_replay_validator_imports_projection_public_contracts_only():
    source = Path(replay_validator.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    private_projection_imports = []
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "Virus_Scan.scheduler.replay.replay_projection":
            private_projection_imports.extend(alias.name for alias in node.names if alias.name.startswith("_"))
    assert private_projection_imports == []
