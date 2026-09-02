"""Canonical replay-learning model package.

Production callers enter through :mod:`Virus_Scan.models.replay.api` or the
bounded replay-learning public contract.  The package root preserves only the
historical public persistence entrypoint; private alternate exports are not
published here.
"""
from __future__ import annotations

from Virus_Scan.models.replay.api import persist_parent_learning_from_results

__all__ = ("persist_parent_learning_from_results",)
