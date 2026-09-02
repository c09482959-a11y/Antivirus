import ast
from pathlib import Path

from Virus_Scan.runtime.environment import runtime_worker_shared_persistence_writes_disabled
from Virus_Scan.scheduler.api.runtime import scheduler_worker_shared_persistence_writes_disabled

MODEL_PERSISTENCE_FILES = (
    Path("Virus_Scan/models/profiles/api.py"),
    Path("Virus_Scan/models/replay/learning.py"),
)
JSON_PUBLICATION_FILE = Path("Virus_Scan/core/jsonio.py")


def _import_modules(path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            modules.append(node.module or "")
        elif isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
    return tuple(modules)


def test_model_persistence_uses_runtime_owned_worker_policy_not_scheduler_api():
    for path in MODEL_PERSISTENCE_FILES:
        imported_modules = _import_modules(path)
        assert "Virus_Scan.scheduler.api.runtime" not in imported_modules
        assert "Virus_Scan.runtime.environment" in imported_modules


def test_json_publication_has_no_removed_profile_worker_persistence_policy():
    imported_modules = _import_modules(JSON_PUBLICATION_FILE)
    assert "Virus_Scan.scheduler.api.runtime" not in imported_modules
    assert "Virus_Scan.runtime.environment" not in imported_modules


def test_runtime_worker_json_policy_matches_existing_scheduler_public_contract():
    parent_env = {"UMIGE_PROCESS_SHARD": "0", "UMIGE_PROCESS_QUEUE": "0", "UMIGE_INMEMORY_WORKER": "0"}
    shard_env = {"UMIGE_PROCESS_SHARD": "1"}
    queue_env = {"UMIGE_PROCESS_QUEUE": "1"}
    in_memory_env = {"UMIGE_INMEMORY_WORKER": "1"}
    disabled_text_env = {"UMIGE_PROCESS_QUEUE": "false", "UMIGE_INMEMORY_WORKER": "off"}

    for env in (parent_env, shard_env, queue_env, in_memory_env, disabled_text_env):
        assert scheduler_worker_shared_persistence_writes_disabled(env) is runtime_worker_shared_persistence_writes_disabled(env)


def test_models_do_not_import_scheduler_runtime_for_worker_write_identity():
    for path in Path("Virus_Scan/models").rglob("*.py"):
        imported_modules = _import_modules(path)
        assert "Virus_Scan.scheduler.api.runtime" not in imported_modules
        assert "Virus_Scan.scheduler.runtime.multiprocessing_context" not in imported_modules
