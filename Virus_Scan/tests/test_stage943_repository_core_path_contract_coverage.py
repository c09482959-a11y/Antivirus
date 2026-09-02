from pathlib import Path

from Virus_Scan.core.path_utils import ensure_parent_dir, safe_child_path


def test_safe_child_path_accepts_nested_relative_member_inside_root(tmp_path: Path):
    root = tmp_path / "scan_root"
    root.mkdir()

    child = safe_child_path(root, "nested/payload.bin")

    assert child == (root / "nested" / "payload.bin").resolve()
    assert root.resolve() in child.parents


def test_safe_child_path_rejects_empty_absolute_and_traversal_members(tmp_path: Path):
    root = tmp_path / "scan_root"
    root.mkdir()

    assert safe_child_path(root, "") is None
    assert safe_child_path(root, str(tmp_path / "outside.bin")) is None
    assert safe_child_path(root, "../outside.bin") is None
    assert safe_child_path(root, "nested/../../outside.bin") is None


def test_ensure_parent_dir_creates_only_parent_and_returns_target_path(tmp_path: Path):
    target = tmp_path / "a" / "b" / "result.json"

    returned = ensure_parent_dir(target)

    assert returned == target
    assert target.parent.is_dir()
    assert not target.exists()
