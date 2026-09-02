"""Process-local re-entrant lease context for the scheduler stage-budget owner."""
from __future__ import annotations

from contextvars import ContextVar, Token


_ACTIVE_STAGE_BUDGET_SEMAPHORE_IDS: ContextVar[tuple[int, ...]] = ContextVar(
    "active_scheduler_stage_budget_semaphore_ids",
    default=(),
)


class SchedulerStageBudgetLease(list):
    """Acquired tokens plus immutable process-local re-entrancy ownership."""

    def __init__(
        self,
        tokens: object=(),
        *,
        evidence: object=(),
        context_token: Token[tuple[int, ...]] | None = None,
        inherited: bool = False,
    ) -> None:
        super().__init__(tokens or ())
        self.evidence = tuple(evidence or ())
        self.context_token = context_token
        self.inherited = inherited


def inherit_stage_budget_lease(semaphore: object) -> SchedulerStageBudgetLease | None:
    """Enter a nested lease when the current context already owns the semaphore."""
    semaphore_id = id(semaphore)
    active_ids = _ACTIVE_STAGE_BUDGET_SEMAPHORE_IDS.get()
    if semaphore_id not in active_ids:
        return None
    token = _ACTIVE_STAGE_BUDGET_SEMAPHORE_IDS.set(active_ids + (semaphore_id,))
    return SchedulerStageBudgetLease(context_token=token, inherited=True)


def own_stage_budget_lease(
    semaphore: object,
    tokens: object,
) -> SchedulerStageBudgetLease:
    """Record a newly acquired semaphore lease in the current execution context."""
    semaphore_id = id(semaphore)
    active_ids = _ACTIVE_STAGE_BUDGET_SEMAPHORE_IDS.get()
    token = _ACTIVE_STAGE_BUDGET_SEMAPHORE_IDS.set(active_ids + (semaphore_id,))
    return SchedulerStageBudgetLease(tokens, context_token=token)


def reset_stage_budget_lease_context(lease: SchedulerStageBudgetLease) -> None:
    """Leave the exact execution context entered for a stage-budget lease."""
    token = lease.context_token
    if token is not None:
        _ACTIVE_STAGE_BUDGET_SEMAPHORE_IDS.reset(token)


__all__ = (
    "SchedulerStageBudgetLease",
    "inherit_stage_budget_lease",
    "own_stage_budget_lease",
    "reset_stage_budget_lease_context",
)
