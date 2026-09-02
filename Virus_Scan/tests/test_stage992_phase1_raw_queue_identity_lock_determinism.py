import ast
import hashlib
from pathlib import Path

from Virus_Scan.scheduler.queue import identity_lock


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "Virus_Scan" / "scheduler" / "queue" / "identity_lock.py"


def test_identity_lock_source_never_uses_process_hash_fallback():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    hash_calls = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "hash"
    ]
    assert hash_calls == []


def test_identity_lock_digest_is_full_sha256_and_deterministic(tmp_path):
    identity = "raw:file-stage992:collector:7:1"
    expected = hashlib.sha256(identity.encode("utf-8", "surrogatepass")).hexdigest()

    decision = identity_lock.acquire_identity_lock_decision(tmp_path, identity)

    assert decision.acquired is True
    assert decision.lock_path is not None
    assert decision.lock_path.stem == expected
    assert len(decision.lock_path.stem) == 64
    assert identity_lock.release_identity_lock_decision(decision.lock_path).released is True


def test_identity_lock_fails_closed_for_unrepresentable_identity(tmp_path):
    class BadIdentity:
        def __str__(self):  # pragma: no cover
            raise ValueError("identity text unavailable")

    assert identity_lock.acquire_identity_lock_decision(tmp_path, BadIdentity()).acquired is False
