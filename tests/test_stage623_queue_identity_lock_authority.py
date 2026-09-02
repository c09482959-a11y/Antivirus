import ast
from pathlib import Path

from Virus_Scan.scheduler.queue import identity_lock as process_queue_identity_lock
from Virus_Scan.scheduler.queue import publish as process_queue_publish


def test_process_queue_identity_locks_are_implemented_in_identity_lock_owner():
    source = Path(process_queue_identity_lock.__file__).read_text(encoding="utf-8")
    assert "def acquire_identity_lock_decision" in source
    assert "def release_identity_lock_decision" in source
    assert "def acquire_identity_lock(" not in source
    assert "def release_identity_lock(" not in source
    assert "def queue_identity_lock_dir" in source
    assert "identity_locks" in source
    assert "from Virus_Scan.scheduler.ownership.scheduler_identity import" not in source


def test_process_queue_publish_and_recovery_use_identity_lock_owner():
    for module in (process_queue_publish,):
        source = Path(module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        authority_imports = {
            alias.name: alias.asname
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.module == "Virus_Scan.scheduler.queue.identity_lock"
            for alias in node.names
        }
        assert authority_imports == {
            "acquire_identity_lock_decision": "_queue_acquire_identity_lock_decision",
            "release_identity_lock_decision": "_queue_release_identity_lock_decision",
        }
        assert "from Virus_Scan.scheduler.ownership.scheduler_identity import" not in source
        identity_imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.module == "Virus_Scan.scheduler.queue.identity"
            for alias in node.names
        }
        assert "acquire_identity_lock" not in identity_imports
        assert "release_identity_lock" not in identity_imports
