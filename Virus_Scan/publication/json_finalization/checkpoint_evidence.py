"""Durable retained-checkpoint evidence publication."""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from Virus_Scan.exception_contracts import TELEMETRY_FAILURE_ERRORS
from Virus_Scan.publication.json_finalization.checkpoint_journal import (
    is_checkpoint_journal,
    materialize_checkpoint_journal,
)
from Virus_Scan.runtime.api import durable_replace_regular_file


def partial_output_path(path: str) -> str:
    return path + ".partial"


def checkpoint_evidence_path(path: str) -> str:
    return path + ".partial.checkpoint.json"


def preserve_checkpoint_evidence(path: str) -> bool:
    partial = Path(partial_output_path(path))
    checkpoint = Path(checkpoint_evidence_path(path))
    try:
        if not partial.exists():
            return False
        if is_checkpoint_journal(partial):
            materialize_checkpoint_journal(partial, checkpoint)
        else:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=checkpoint.name + ".",
                suffix=".tmp",
                dir=checkpoint.parent,
            )
            os.close(descriptor)
            temporary = Path(temporary_name)
            try:
                shutil.copyfile(partial, temporary)
                durable_replace_regular_file(temporary, checkpoint)
            finally:
                temporary.unlink(missing_ok=True)
        return True
    except TELEMETRY_FAILURE_ERRORS:
        return False


__all__ = (
    "checkpoint_evidence_path",
    "partial_output_path",
    "preserve_checkpoint_evidence",
)
