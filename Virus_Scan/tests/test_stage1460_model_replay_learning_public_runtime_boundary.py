import ast
from pathlib import Path

from Virus_Scan.models.replay import learning


def test_stage1460_replay_learning_uses_public_runtime_worker_json_policy_name():
    source = Path(learning.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    private_runtime_imports = []
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "Virus_Scan.runtime.environment":
            for alias in node.names:
                local_name = alias.asname or alias.name
                if local_name.startswith("_"):
                    private_runtime_imports.append(local_name)
    assert private_runtime_imports == []
    assert "_umige_shared_persistence_worker_writes_disabled" not in vars(learning)
    assert "runtime_worker_shared_persistence_writes_disabled" in vars(learning)
