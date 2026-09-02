"""Public model-learning reentry context contract.

The learning subsystem owns reentry state.  Profile learning callers use this
public boundary so they do not import learning implementation internals or own
thread-local learning guards themselves.
"""
from __future__ import annotations

from Virus_Scan.models.learning import learning_guard as owner_learning_guard

learning_guard = owner_learning_guard

__all__ = ("learning_guard",)
