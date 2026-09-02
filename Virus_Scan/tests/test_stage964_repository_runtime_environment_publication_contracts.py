from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
import os
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

from Virus_Scan.runtime.context import RuntimeContext
from Virus_Scan.runtime.environment import RuntimeEnvironmentOwner
from Virus_Scan.orchestration.lifecycle import prepare_scan


@contextmanager
def _preserved_umige_environment(*names: str):
    previous = {name: os.environ.get(name) for name in names}
    try:
        for name in names:
            os.environ.pop(name, None)
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def test_stage964_runtime_environment_owner_validates_umige_keys_and_snapshots_sorted():
    names = (
        "UMIGE_STAGE964_ALPHA",
        "UMIGE_STAGE964_BETA",
        "UMIGE_STAGE964_IGNORED",
    )
    with _preserved_umige_environment(*names):
        owner = RuntimeEnvironmentOwner()

        written = owner.publish({
            "UMIGE_STAGE964_BETA": 7,
            "UMIGE_STAGE964_IGNORED": None,
            "UMIGE_STAGE964_ALPHA": "enabled",
        })

        assert written == {
            "UMIGE_STAGE964_BETA": "7",
            "UMIGE_STAGE964_ALPHA": "enabled",
        }
        assert owner.published == written
        assert isinstance(RuntimeContext().environment, RuntimeEnvironmentOwner)
        assert owner.snapshot("UMIGE_STAGE964_") == {
            "UMIGE_STAGE964_ALPHA": "enabled",
            "UMIGE_STAGE964_BETA": "7",
        }
        assert "UMIGE_STAGE964_IGNORED" not in os.environ


def test_stage964_runtime_environment_owner_rejects_non_umige_publication_without_hidden_write():
    names = ("NOT_UMIGE_STAGE964", "UMIGE_STAGE964_VALID")
    with _preserved_umige_environment(*names):
        owner = RuntimeEnvironmentOwner()

        try:
            owner.publish({"NOT_UMIGE_STAGE964": "bad", "UMIGE_STAGE964_VALID": "ok"})
        except ValueError as exc:
            assert "invalid_runtime_environment_key" in str(exc)
        else:
            raise AssertionError("non-UMIGE environment key was accepted")

        assert "NOT_UMIGE_STAGE964" not in os.environ
        assert "UMIGE_STAGE964_VALID" not in os.environ
        assert owner.published == {}


def test_stage964_publish_defaults_and_prepare_scan_preserve_existing_runtime_defaults(tmp_path: Path):
    names = (
        "UMIGE_ARCHIVE_MAX_DEPTH",
        "UMIGE_STAGE964_CONFIG_ONLY",
        "UMIGE_STAGE_PARALLEL",
        "UMIGE_STAGE_PARALLEL_WORKERS",
        "UMIGE_STAGE_PARALLEL_MODE",
    )
    with _preserved_umige_environment(*names):
        os.environ["UMIGE_ARCHIVE_MAX_DEPTH"] = "preexisting"
        environment = RuntimeEnvironmentOwner()
        owner_updates: list[dict[str, object]] = []
        fake_runtime = SimpleNamespace(
            parent_cli=False,
            scan_started_at=0.0,
            environment=environment,
            config=SimpleNamespace(
                env_mapping=lambda: {
                    "UMIGE_ARCHIVE_MAX_DEPTH": "2",
                    "UMIGE_STAGE964_CONFIG_ONLY": "from_config",
                },
                stage_limits=SimpleNamespace(as_dict=lambda: {"generic": 8}),
                archive_limits={"max_depth": 2},
                persistence={"output_path": str(tmp_path / "scan_results.json")},
                economics=SimpleNamespace(marker="economics"),
            ),
            owner=SimpleNamespace(update=lambda values, domain="runtime": owner_updates.append(dict(values))),
        )
        args = SimpleNamespace(
            output=str(tmp_path / "scan_results.json"),
            preserve_scan_results=False,
            no_stage_parallel=True,
            stage_parallel_workers=999,
            stage_parallel_mode="PROCESS",
        )

        prepare_scan(fake_runtime, args)

        assert os.environ["UMIGE_STAGE_PARALLEL"] == "0"
        assert os.environ["UMIGE_STAGE_PARALLEL_WORKERS"] == "16"
        assert os.environ["UMIGE_STAGE_PARALLEL_MODE"] == "process"
        assert os.environ["UMIGE_ARCHIVE_MAX_DEPTH"] == "preexisting"
        assert os.environ["UMIGE_STAGE964_CONFIG_ONLY"] == "from_config"
        assert fake_runtime.scan_started_at > 0.0
        assert owner_updates, "prepare_scan did not publish runtime owner configuration"
        assert owner_updates[-1]["UMIGE_SHARED_STAGE_LIMITS"] == {"generic": 8}
        assert owner_updates[-1]["UMIGE_ARCHIVE_QUOTA_POLICY"] == {"max_depth": 2}
        assert owner_updates[-1]["UMIGE_FAULT_DOMAIN_POLICY"] == "contain"


def test_stage964_runtime_environment_boundary_has_no_dynamic_or_function_scope_imports():
    source = read_python_file(Path("Virus_Scan/runtime/environment.py"))
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent

    for node in ast.walk(tree):
        assert not (
            isinstance(node, (ast.Import, ast.ImportFrom))
            and not isinstance(getattr(node, "parent", None), ast.Module)
        )
        assert not (
            isinstance(node, ast.Call)
            and (
                getattr(node.func, "id", "") == "__import__"
                or getattr(node.func, "attr", "") == "import_module"
            )
        )
