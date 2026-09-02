"""Public scheduler validation and error contracts.

The raw queue lifecycle imports these typed exceptions instead of defining
contracts inside the monolith.  Keeping error taxonomy outside lifecycle code
makes claim/reclaim/finalize boundaries importable without scheduler side
effects.
"""
from __future__ import annotations

import json

RAW_QUEUE_RECOVERABLE_EXCEPTIONS = (OSError, ValueError, TypeError, RuntimeError, KeyError, AttributeError, json.JSONDecodeError)
RAW_QUEUE_TELEMETRY_EXCEPTIONS = (OSError, RuntimeError, ValueError, TypeError, AttributeError)


class RawRangeReadError(OSError):
    """Raw queue range read failed and must be handled as degraded work."""


class QueueIdentityScanError(RuntimeError):
    """Queue identity enumeration failed; enqueue/claim must fail closed."""


class HybridQueueStateError(RuntimeError):
    """Hybrid queue state cache could not be updated deterministically."""


class QueueResultMergeError(RuntimeError):
    """Durable queue result merge/readback failed and must fail closed."""


class QueueResultReadError(QueueResultMergeError):
    """Durable queue result read/list operation failed and must produce evidence."""


class QueueResultSchemaError(QueueResultMergeError):
    """Durable queue result or done-job schema was invalid and must produce evidence."""


class QueueResultMissingError(QueueResultMergeError):
    """Done queue job lacked a corresponding durable result or identity."""


class QueueRetryPolicyError(RuntimeError):
    """Queue retry bookkeeping failed and must remain replay-visible."""


class SchedulerTypeContractError(TypeError, RuntimeError):
    """Scheduler type-contract violation with hard-fail semantics."""


class SchedulerFinalizationOwnershipError(RuntimeError):
    """Finalization retained live worker or pending queue ownership."""

    def __init__(self, ownership_kind: str, identities: tuple[str, ...]) -> None:
        super().__init__("scheduler finalization has " + ownership_kind + ": " + ", ".join(identities))


class SchedulerFinalizationCountContractError(ValueError):
    """Finalization count could not be projected to the strict integer contract."""


class SchedulerFinalizationCountMismatchError(RuntimeError):
    """Finalized and emitted result counts disagree."""

    def __init__(self, emitted: int, finalized: int) -> None:
        super().__init__(
            "scheduler finalization result mismatch: emitted="
            + str(emitted)
            + " finalized="
            + str(finalized)
        )


class SchedulerReplayEvidenceSequenceError(RuntimeError):
    """Replay evidence was not a supported deterministic sequence."""

    def __init__(self) -> None:
        super().__init__("scheduler replay evidence sequence is malformed")


class SchedulerReplayMissingJobIdentityError(RuntimeError):
    """Replay result lacked both a canonical job id and file identity."""

    def __init__(self) -> None:
        super().__init__("scheduler replay result missing job identity")


class SchedulerReplayMissingFilePathError(RuntimeError):
    """Replay result lacked the file path required for stable identity."""

    def __init__(self) -> None:
        super().__init__("scheduler replay result missing file path")


class SchedulerReplayMissingFieldError(RuntimeError):
    """Replay result lacked a required canonical label field."""

    def __init__(self, field_text: str) -> None:
        super().__init__("scheduler replay result missing " + field_text)
