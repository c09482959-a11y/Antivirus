import ast
from pathlib import Path

from Virus_Scan.runtime.provenance import make_failure_provenance, reset_provenance_epoch


def test_stage1009_runtime_provenance_context_coercion_preserves_valid_context() -> None:
    reset_provenance_epoch()
    provenance = make_failure_provenance(
        domain="scheduler",
        where="queue_retry",
        error_type="RuntimeError",
        message="failed",
        fingerprint="fingerprint",
        correlation_id="correlation",
        fatal=True,
        unsafe_to_continue=True,
        continuation_policy="fatal_explicit",
        context={
            "parent_chain": ["root", "worker"],
            "retry_generation": "7",
            "scheduler_epoch": "11",
            "queue_identity": "sample.bin",
        },
    )

    assert provenance.parent_chain == ("root", "worker")
    assert provenance.retry_generation == 7
    assert provenance.scheduler_epoch == 11
    assert provenance.queue_identity == "sample.bin"


def test_stage1009_runtime_provenance_malformed_context_uses_bounded_exceptions_only() -> None:
    reset_provenance_epoch()
    provenance = make_failure_provenance(
        domain="scheduler",
        where="queue_retry",
        error_type="RuntimeError",
        message="failed",
        fingerprint="fingerprint",
        correlation_id="correlation",
        fatal=True,
        unsafe_to_continue=True,
        continuation_policy="fatal_explicit",
        context={
            "parent_chain": object(),
            "retry_generation": "not-an-int",
            "queue_epoch": "also-not-an-int",
            "queue_identity": "sample.bin",
        },
    )

    assert provenance.parent_chain == ()
    assert provenance.retry_generation == 0
    assert provenance.scheduler_epoch == 0
    assert provenance.queue_identity == "sample.bin"


def test_stage1009_runtime_provenance_has_no_broad_clean_context_fallbacks() -> None:
    source_path = Path("Virus_Scan/runtime/provenance.py")
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    broad_handler_lines: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        if node.type is None:
            broad_handler_lines.append(node.lineno)
            continue
        if isinstance(node.type, ast.Name) and node.type.id in {"BaseException", "Exception"}:
            # _safe_text/stable digest can convert unprintable values to text, but the
            # provenance context coercion path must not use broad handlers to erase
            # scheduler/queue retry metadata into clean defaults.
            handler_text = ast.get_source_segment(source_path.read_text(encoding="utf-8"), node) or ""
            if "retry_generation" in handler_text or "scheduler_epoch" in handler_text or "parent_chain" in handler_text:
                broad_handler_lines.append(node.lineno)
    assert broad_handler_lines == []
