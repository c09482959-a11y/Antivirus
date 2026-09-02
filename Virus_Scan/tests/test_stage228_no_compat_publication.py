from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_shared_state_publication_modules_removed():
    assert not (ROOT / "runtime" / "shared_state.py").exists()
    assert not (ROOT / "runtime" / "state.py").exists()


def test_removed_publication_api_names_absent_from_runtime_production():
    forbidden = ("set" + "_shared", "sync" + "_modules", "publish" + "_shared_values")
    offenders = []
    for path in (ROOT / "runtime").rglob("*.py"):
        if path.name.startswith("test_"):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for name in forbidden:
            if name in text:
                offenders.append((path.relative_to(ROOT).as_posix(), name))
    assert offenders == []
