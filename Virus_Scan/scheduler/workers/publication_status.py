"""No-hook worker publication status/context boundaries."""
from __future__ import annotations



from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.scheduler.workers.no_hook_scalars import worker_bool


def safe_publication_status(value: object) -> tuple[bool, str]:
    status, reason = worker_bool(value, replacement=False, reason="scheduler_worker_publication_status_rejected")
    return status, reason


def safe_publication_context(context: object, *, replacement_text: str) -> str:
    text, reason = no_hook_text(
        context,
        missing_reason="missing_scheduler_publication_context",
        unsupported_reason="unsafe_scheduler_publication_context_rejected",
    )
    if reason:
        return replacement_text
    stripped = str.strip(text)
    return stripped or replacement_text


__all__ = ("safe_publication_context", "safe_publication_status")
