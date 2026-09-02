import ast
from pathlib import Path


SCHED = Path(__file__).resolve().parents[1] / "scheduler"
CANONICAL_OWNER = "internal/output_publication.py"
CANONICAL_MODULE = "Virus_Scan.scheduler.internal.output_publication"
CANONICAL_SYMBOL = "write_worker_output_payload"
CANONICAL_CALLERS = frozenset(
    {
        "evidence/process_queue_partial_output_steps.py",
        "queue/process_queue_result_merge_outputs.py",
        "queue/terminal_missing_finalization_support.py",
        "workers/child_result_publication.py",
    }
)
DELETED_PUBLICATION_IDENTITIES = frozenset(
    {
        "_write_worker_output_fast",
        "write_worker_output_fast",
        "write_required_worker_output",
        "WorkerOutputWriter",
        "WorkerOutputBuffer",
        "QueueChildOutputBufferConfigDecision",
        "parse_queue_child_output_buffer_config_decision",
        "Virus_Scan.scheduler.workers.output_publication",
    }
)
DELETED_PUBLICATION_INJECTION_NAMES = frozenset(
    {
        "finalize_missing_file_accounting",
        "output_buffer",
        "write_partial_output",
        "write_worker_output",
    }
)


def _scheduler_sources() -> dict[str, str]:
    return {
        path.relative_to(SCHED).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(SCHED.rglob("*.py"))
        if "__pycache__" not in path.parts
    }


def test_stage723_worker_output_publication_has_one_implementation_owner() -> None:
    sources = _scheduler_sources()
    definition_owners = {
        relative
        for relative, source in sources.items()
        if any(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == CANONICAL_SYMBOL
            for node in ast.parse(source).body
        )
    }

    assert definition_owners == {CANONICAL_OWNER}
    owner_source = sources[CANONICAL_OWNER]
    assert "from Virus_Scan.contracts.worker_record import make_json_safe" in owner_source
    assert "flush_open_writable_file(handle.fileno())" in owner_source
    assert "durable_replace_regular_file(temporary_path, target)" in owner_source
    assert '__all__ = ("write_worker_output_payload",)' in owner_source


def test_stage723_worker_output_publication_has_exactly_four_production_callers() -> None:
    callers: set[str] = set()
    for relative, source in _scheduler_sources().items():
        tree = ast.parse(source)
        imports_writer = any(
            isinstance(node, ast.ImportFrom)
            and node.module == CANONICAL_MODULE
            and any(alias.name == CANONICAL_SYMBOL for alias in node.names)
            for node in ast.walk(tree)
        )
        if not imports_writer:
            continue
        assert any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == CANONICAL_SYMBOL
            for node in ast.walk(tree)
        )
        callers.add(relative)

    assert callers == CANONICAL_CALLERS


def test_stage723_deleted_publication_paths_have_no_production_reachability() -> None:
    lexical_offenders: list[tuple[str, str]] = []
    injection_offenders: list[tuple[str, int, str]] = []
    for relative, source in _scheduler_sources().items():
        for identity in DELETED_PUBLICATION_IDENTITIES:
            if identity in source:
                lexical_offenders.append((relative, identity))
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                if node.target.id in DELETED_PUBLICATION_INJECTION_NAMES:
                    injection_offenders.append((relative, node.lineno, node.target.id))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                arguments = (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
                for argument in arguments:
                    if argument.arg in DELETED_PUBLICATION_INJECTION_NAMES:
                        injection_offenders.append((relative, node.lineno, argument.arg))

    assert lexical_offenders == []
    assert injection_offenders == []


def test_stage723_worker_record_contract_has_one_scheduler_importer() -> None:
    importers = set()
    for relative, source in _scheduler_sources().items():
        tree = ast.parse(source)
        if any(
            isinstance(node, ast.ImportFrom)
            and node.module == "Virus_Scan.contracts.worker_record"
            for node in ast.walk(tree)
        ):
            importers.add(relative)

    assert importers == {CANONICAL_OWNER}
